rule TTP_XOR_WriteProcessMemory_3876 {
  strings:
    $key_3876 = { 6f 04 [2] 5d 26 [2] 5b 13 [2] 75 13 [2] 4a 0f }

  condition:
    any of them
}