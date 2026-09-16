rule TTP_XOR_WriteProcessMemory_81d9 {
  strings:
    $key_81d9 = { d6 ab [2] e4 89 [2] e2 bc [2] cc bc [2] f3 a0 }

  condition:
    any of them
}