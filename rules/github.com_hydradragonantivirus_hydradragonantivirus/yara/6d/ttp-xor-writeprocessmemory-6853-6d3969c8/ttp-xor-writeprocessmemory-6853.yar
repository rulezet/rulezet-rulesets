rule TTP_XOR_WriteProcessMemory_6853 {
  strings:
    $key_6853 = { 3f 21 [2] 0d 03 [2] 0b 36 [2] 25 36 [2] 1a 2a }

  condition:
    any of them
}