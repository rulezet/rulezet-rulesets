rule TTP_XOR_WriteProcessMemory_6872 {
  strings:
    $key_6872 = { 3f 00 [2] 0d 22 [2] 0b 17 [2] 25 17 [2] 1a 0b }

  condition:
    any of them
}