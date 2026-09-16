rule TTP_XOR_WriteProcessMemory_6806 {
  strings:
    $key_6806 = { 3f 74 [2] 0d 56 [2] 0b 63 [2] 25 63 [2] 1a 7f }

  condition:
    any of them
}