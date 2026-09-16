rule TTP_XOR_WriteProcessMemory_97e0 {
  strings:
    $key_97e0 = { c0 92 [2] f2 b0 [2] f4 85 [2] da 85 [2] e5 99 }

  condition:
    any of them
}