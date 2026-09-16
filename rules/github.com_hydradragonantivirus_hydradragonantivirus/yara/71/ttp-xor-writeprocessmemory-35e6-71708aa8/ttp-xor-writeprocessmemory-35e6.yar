rule TTP_XOR_WriteProcessMemory_35e6 {
  strings:
    $key_35e6 = { 62 94 [2] 50 b6 [2] 56 83 [2] 78 83 [2] 47 9f }

  condition:
    any of them
}