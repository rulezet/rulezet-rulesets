rule TTP_XOR_WriteProcessMemory_10c5 {
  strings:
    $key_10c5 = { 47 b7 [2] 75 95 [2] 73 a0 [2] 5d a0 [2] 62 bc }

  condition:
    any of them
}