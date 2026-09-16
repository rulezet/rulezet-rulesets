rule TTP_XOR_WriteProcessMemory_1373 {
  strings:
    $key_1373 = { 44 01 [2] 76 23 [2] 70 16 [2] 5e 16 [2] 61 0a }

  condition:
    any of them
}