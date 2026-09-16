rule TTP_XOR_WriteProcessMemory_2d71 {
  strings:
    $key_2d71 = { 7a 03 [2] 48 21 [2] 4e 14 [2] 60 14 [2] 5f 08 }

  condition:
    any of them
}