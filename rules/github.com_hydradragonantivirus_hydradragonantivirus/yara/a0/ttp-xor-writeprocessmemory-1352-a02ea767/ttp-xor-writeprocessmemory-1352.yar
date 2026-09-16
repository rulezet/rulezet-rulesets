rule TTP_XOR_WriteProcessMemory_1352 {
  strings:
    $key_1352 = { 44 20 [2] 76 02 [2] 70 37 [2] 5e 37 [2] 61 2b }

  condition:
    any of them
}