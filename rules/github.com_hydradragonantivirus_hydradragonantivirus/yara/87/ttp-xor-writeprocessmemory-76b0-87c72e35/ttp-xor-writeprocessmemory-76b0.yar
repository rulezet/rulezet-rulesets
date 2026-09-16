rule TTP_XOR_WriteProcessMemory_76b0 {
  strings:
    $key_76b0 = { 21 c2 [2] 13 e0 [2] 15 d5 [2] 3b d5 [2] 04 c9 }

  condition:
    any of them
}