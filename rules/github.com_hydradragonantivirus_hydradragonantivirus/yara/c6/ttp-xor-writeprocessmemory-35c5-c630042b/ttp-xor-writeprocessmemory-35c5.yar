rule TTP_XOR_WriteProcessMemory_35c5 {
  strings:
    $key_35c5 = { 62 b7 [2] 50 95 [2] 56 a0 [2] 78 a0 [2] 47 bc }

  condition:
    any of them
}