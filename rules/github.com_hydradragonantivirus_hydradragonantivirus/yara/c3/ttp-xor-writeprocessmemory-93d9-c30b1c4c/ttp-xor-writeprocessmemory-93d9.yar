rule TTP_XOR_WriteProcessMemory_93d9 {
  strings:
    $key_93d9 = { c4 ab [2] f6 89 [2] f0 bc [2] de bc [2] e1 a0 }

  condition:
    any of them
}