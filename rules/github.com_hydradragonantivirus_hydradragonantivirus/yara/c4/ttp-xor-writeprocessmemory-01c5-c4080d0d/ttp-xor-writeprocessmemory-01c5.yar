rule TTP_XOR_WriteProcessMemory_01c5 {
  strings:
    $key_01c5 = { 56 b7 [2] 64 95 [2] 62 a0 [2] 4c a0 [2] 73 bc }

  condition:
    any of them
}