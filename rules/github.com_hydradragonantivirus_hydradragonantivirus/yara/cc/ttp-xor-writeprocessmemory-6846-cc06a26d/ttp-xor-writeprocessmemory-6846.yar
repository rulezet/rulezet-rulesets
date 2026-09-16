rule TTP_XOR_WriteProcessMemory_6846 {
  strings:
    $key_6846 = { 3f 34 [2] 0d 16 [2] 0b 23 [2] 25 23 [2] 1a 3f }

  condition:
    any of them
}