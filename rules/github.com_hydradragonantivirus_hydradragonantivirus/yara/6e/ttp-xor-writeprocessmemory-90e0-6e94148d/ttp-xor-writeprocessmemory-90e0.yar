rule TTP_XOR_WriteProcessMemory_90e0 {
  strings:
    $key_90e0 = { c7 92 [2] f5 b0 [2] f3 85 [2] dd 85 [2] e2 99 }

  condition:
    any of them
}