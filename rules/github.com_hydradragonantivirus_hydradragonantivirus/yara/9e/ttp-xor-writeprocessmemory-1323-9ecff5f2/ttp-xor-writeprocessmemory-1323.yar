rule TTP_XOR_WriteProcessMemory_1323 {
  strings:
    $key_1323 = { 44 51 [2] 76 73 [2] 70 46 [2] 5e 46 [2] 61 5a }

  condition:
    any of them
}