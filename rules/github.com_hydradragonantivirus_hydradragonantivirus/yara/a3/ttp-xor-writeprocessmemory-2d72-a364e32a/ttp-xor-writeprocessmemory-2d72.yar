rule TTP_XOR_WriteProcessMemory_2d72 {
  strings:
    $key_2d72 = { 7a 00 [2] 48 22 [2] 4e 17 [2] 60 17 [2] 5f 0b }

  condition:
    any of them
}