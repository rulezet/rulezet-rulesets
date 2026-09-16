rule TTP_XOR_WriteProcessMemory_b65c {
  strings:
    $key_b65c = { e1 2e [2] d3 0c [2] d5 39 [2] fb 39 [2] c4 25 }

  condition:
    any of them
}