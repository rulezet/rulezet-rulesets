rule TTP_XOR_WriteProcessMemory_26b0 {
  strings:
    $key_26b0 = { 71 c2 [2] 43 e0 [2] 45 d5 [2] 6b d5 [2] 54 c9 }

  condition:
    any of them
}