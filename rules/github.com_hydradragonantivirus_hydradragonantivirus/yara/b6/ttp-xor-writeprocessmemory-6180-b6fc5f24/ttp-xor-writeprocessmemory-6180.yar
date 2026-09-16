rule TTP_XOR_WriteProcessMemory_6180 {
  strings:
    $key_6180 = { 36 f2 [2] 04 d0 [2] 02 e5 [2] 2c e5 [2] 13 f9 }

  condition:
    any of them
}