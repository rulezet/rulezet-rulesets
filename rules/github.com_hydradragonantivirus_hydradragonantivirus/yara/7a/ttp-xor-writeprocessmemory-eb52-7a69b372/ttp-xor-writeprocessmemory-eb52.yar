rule TTP_XOR_WriteProcessMemory_eb52 {
  strings:
    $key_eb52 = { bc 20 [2] 8e 02 [2] 88 37 [2] a6 37 [2] 99 2b }

  condition:
    any of them
}