rule TTP_XOR_WriteProcessMemory_31c5 {
  strings:
    $key_31c5 = { 66 b7 [2] 54 95 [2] 52 a0 [2] 7c a0 [2] 43 bc }

  condition:
    any of them
}