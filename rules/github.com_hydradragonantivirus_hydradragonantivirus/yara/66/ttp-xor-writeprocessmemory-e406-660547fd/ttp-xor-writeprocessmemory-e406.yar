rule TTP_XOR_WriteProcessMemory_e406 {
  strings:
    $key_e406 = { b3 74 [2] 81 56 [2] 87 63 [2] a9 63 [2] 96 7f }

  condition:
    any of them
}