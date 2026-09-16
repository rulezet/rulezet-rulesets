rule TTP_XOR_WriteProcessMemory_4246 {
  strings:
    $key_4246 = { 15 34 [2] 27 16 [2] 21 23 [2] 0f 23 [2] 30 3f }

  condition:
    any of them
}