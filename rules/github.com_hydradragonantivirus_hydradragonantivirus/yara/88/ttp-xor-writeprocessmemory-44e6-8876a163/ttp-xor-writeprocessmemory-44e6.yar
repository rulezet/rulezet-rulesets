rule TTP_XOR_WriteProcessMemory_44e6 {
  strings:
    $key_44e6 = { 13 94 [2] 21 b6 [2] 27 83 [2] 09 83 [2] 36 9f }

  condition:
    any of them
}