rule TTP_XOR_WriteProcessMemory_2a76 {
  strings:
    $key_2a76 = { 7d 04 [2] 4f 26 [2] 49 13 [2] 67 13 [2] 58 0f }

  condition:
    any of them
}