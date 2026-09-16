rule TTP_XOR_WriteProcessMemory_2d26 {
  strings:
    $key_2d26 = { 7a 54 [2] 48 76 [2] 4e 43 [2] 60 43 [2] 5f 5f }

  condition:
    any of them
}