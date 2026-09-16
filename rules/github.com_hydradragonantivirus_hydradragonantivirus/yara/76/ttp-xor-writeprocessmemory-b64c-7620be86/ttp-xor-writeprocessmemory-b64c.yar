rule TTP_XOR_WriteProcessMemory_b64c {
  strings:
    $key_b64c = { e1 3e [2] d3 1c [2] d5 29 [2] fb 29 [2] c4 35 }

  condition:
    any of them
}