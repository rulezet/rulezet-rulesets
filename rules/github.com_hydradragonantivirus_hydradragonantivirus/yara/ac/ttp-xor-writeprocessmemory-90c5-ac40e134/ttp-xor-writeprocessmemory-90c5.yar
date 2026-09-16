rule TTP_XOR_WriteProcessMemory_90c5 {
  strings:
    $key_90c5 = { c7 b7 [2] f5 95 [2] f3 a0 [2] dd a0 [2] e2 bc }

  condition:
    any of them
}