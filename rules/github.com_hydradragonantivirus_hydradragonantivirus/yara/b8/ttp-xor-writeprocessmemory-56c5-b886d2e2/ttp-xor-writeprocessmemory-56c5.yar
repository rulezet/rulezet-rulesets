rule TTP_XOR_WriteProcessMemory_56c5 {
  strings:
    $key_56c5 = { 01 b7 [2] 33 95 [2] 35 a0 [2] 1b a0 [2] 24 bc }

  condition:
    any of them
}