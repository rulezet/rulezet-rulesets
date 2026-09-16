rule TTP_XOR_WriteProcessMemory_7176 {
  strings:
    $key_7176 = { 26 04 [2] 14 26 [2] 12 13 [2] 3c 13 [2] 03 0f }

  condition:
    any of them
}