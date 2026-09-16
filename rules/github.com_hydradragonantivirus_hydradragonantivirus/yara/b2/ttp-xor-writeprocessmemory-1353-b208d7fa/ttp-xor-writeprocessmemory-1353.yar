rule TTP_XOR_WriteProcessMemory_1353 {
  strings:
    $key_1353 = { 44 21 [2] 76 03 [2] 70 36 [2] 5e 36 [2] 61 2a }

  condition:
    any of them
}