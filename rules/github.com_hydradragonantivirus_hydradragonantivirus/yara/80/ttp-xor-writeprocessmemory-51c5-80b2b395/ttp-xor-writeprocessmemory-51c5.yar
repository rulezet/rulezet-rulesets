rule TTP_XOR_WriteProcessMemory_51c5 {
  strings:
    $key_51c5 = { 06 b7 [2] 34 95 [2] 32 a0 [2] 1c a0 [2] 23 bc }

  condition:
    any of them
}