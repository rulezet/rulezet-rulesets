rule TTP_XOR_WriteProcessMemory_55e6 {
  strings:
    $key_55e6 = { 02 94 [2] 30 b6 [2] 36 83 [2] 18 83 [2] 27 9f }

  condition:
    any of them
}