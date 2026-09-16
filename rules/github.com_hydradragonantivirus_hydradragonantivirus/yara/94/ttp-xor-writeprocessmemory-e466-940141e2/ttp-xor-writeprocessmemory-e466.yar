rule TTP_XOR_WriteProcessMemory_e466 {
  strings:
    $key_e466 = { b3 14 [2] 81 36 [2] 87 03 [2] a9 03 [2] 96 1f }

  condition:
    any of them
}