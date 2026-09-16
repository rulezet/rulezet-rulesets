rule TTP_XOR_WriteProcessMemory_1341 {
  strings:
    $key_1341 = { 44 33 [2] 76 11 [2] 70 24 [2] 5e 24 [2] 61 38 }

  condition:
    any of them
}