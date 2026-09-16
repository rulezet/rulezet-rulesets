rule TTP_XOR_WriteProcessMemory_6856 {
  strings:
    $key_6856 = { 3f 24 [2] 0d 06 [2] 0b 33 [2] 25 33 [2] 1a 2f }

  condition:
    any of them
}