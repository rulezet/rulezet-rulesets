rule TTP_XOR_WriteProcessMemory_9eb0 {
  strings:
    $key_9eb0 = { c9 c2 [2] fb e0 [2] fd d5 [2] d3 d5 [2] ec c9 }

  condition:
    any of them
}