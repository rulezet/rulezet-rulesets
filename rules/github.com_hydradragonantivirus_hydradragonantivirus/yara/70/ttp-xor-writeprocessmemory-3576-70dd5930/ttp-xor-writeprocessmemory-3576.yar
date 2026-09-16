rule TTP_XOR_WriteProcessMemory_3576 {
  strings:
    $key_3576 = { 62 04 [2] 50 26 [2] 56 13 [2] 78 13 [2] 47 0f }

  condition:
    any of them
}