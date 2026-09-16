rule TTP_XOR_WriteProcessMemory_44f6 {
  strings:
    $key_44f6 = { 13 84 [2] 21 a6 [2] 27 93 [2] 09 93 [2] 36 8f }

  condition:
    any of them
}