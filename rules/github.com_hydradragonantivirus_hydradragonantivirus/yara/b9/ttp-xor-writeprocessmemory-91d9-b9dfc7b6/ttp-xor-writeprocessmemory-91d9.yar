rule TTP_XOR_WriteProcessMemory_91d9 {
  strings:
    $key_91d9 = { c6 ab [2] f4 89 [2] f2 bc [2] dc bc [2] e3 a0 }

  condition:
    any of them
}