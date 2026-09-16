rule TTP_XOR_WriteProcessMemory_4206 {
  strings:
    $key_4206 = { 15 74 [2] 27 56 [2] 21 63 [2] 0f 63 [2] 30 7f }

  condition:
    any of them
}