rule TTP_XOR_WriteProcessMemory_4216 {
  strings:
    $key_4216 = { 15 64 [2] 27 46 [2] 21 73 [2] 0f 73 [2] 30 6f }

  condition:
    any of them
}