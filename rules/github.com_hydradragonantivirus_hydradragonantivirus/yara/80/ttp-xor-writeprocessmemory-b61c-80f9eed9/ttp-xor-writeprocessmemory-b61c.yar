rule TTP_XOR_WriteProcessMemory_b61c {
  strings:
    $key_b61c = { e1 6e [2] d3 4c [2] d5 79 [2] fb 79 [2] c4 65 }

  condition:
    any of them
}