rule TTP_XOR_WriteProcessMemory_6862 {
  strings:
    $key_6862 = { 3f 10 [2] 0d 32 [2] 0b 07 [2] 25 07 [2] 1a 1b }

  condition:
    any of them
}