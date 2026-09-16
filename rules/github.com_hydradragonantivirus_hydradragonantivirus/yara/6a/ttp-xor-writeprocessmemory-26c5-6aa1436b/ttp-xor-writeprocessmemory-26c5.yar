rule TTP_XOR_WriteProcessMemory_26c5 {
  strings:
    $key_26c5 = { 71 b7 [2] 43 95 [2] 45 a0 [2] 6b a0 [2] 54 bc }

  condition:
    any of them
}