rule TTP_XOR_WriteProcessMemory_15c5 {
  strings:
    $key_15c5 = { 42 b7 [2] 70 95 [2] 76 a0 [2] 58 a0 [2] 67 bc }

  condition:
    any of them
}