rule TTP_XOR_WriteProcessMemory_65c5 {
  strings:
    $key_65c5 = { 32 b7 [2] 00 95 [2] 06 a0 [2] 28 a0 [2] 17 bc }

  condition:
    any of them
}