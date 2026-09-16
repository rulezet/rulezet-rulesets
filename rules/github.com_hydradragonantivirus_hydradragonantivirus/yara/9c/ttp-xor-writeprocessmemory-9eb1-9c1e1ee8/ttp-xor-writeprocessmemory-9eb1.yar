rule TTP_XOR_WriteProcessMemory_9eb1 {
  strings:
    $key_9eb1 = { c9 c3 [2] fb e1 [2] fd d4 [2] d3 d4 [2] ec c8 }

  condition:
    any of them
}