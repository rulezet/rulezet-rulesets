rule TTP_XOR_WriteProcessMemory_07c5 {
  strings:
    $key_07c5 = { 50 b7 [2] 62 95 [2] 64 a0 [2] 4a a0 [2] 75 bc }

  condition:
    any of them
}