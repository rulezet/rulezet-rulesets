rule TTP_XOR_WriteProcessMemory_76c5 {
  strings:
    $key_76c5 = { 21 b7 [2] 13 95 [2] 15 a0 [2] 3b a0 [2] 04 bc }

  condition:
    any of them
}