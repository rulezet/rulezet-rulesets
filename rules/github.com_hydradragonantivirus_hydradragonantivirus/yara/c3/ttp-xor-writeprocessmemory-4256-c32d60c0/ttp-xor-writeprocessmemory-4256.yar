rule TTP_XOR_WriteProcessMemory_4256 {
  strings:
    $key_4256 = { 15 24 [2] 27 06 [2] 21 33 [2] 0f 33 [2] 30 2f }

  condition:
    any of them
}