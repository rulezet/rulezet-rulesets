rule TTP_XOR_WriteProcessMemory_1351 {
  strings:
    $key_1351 = { 44 23 [2] 76 01 [2] 70 34 [2] 5e 34 [2] 61 28 }

  condition:
    any of them
}