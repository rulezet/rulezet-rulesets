rule TTP_XOR_WriteProcessMemory_2c50 {
  strings:
    $key_2c50 = { 7b 22 [2] 49 00 [2] 4f 35 [2] 61 35 [2] 5e 29 }

  condition:
    any of them
}