rule TTP_XOR_WriteProcessMemory_94a0 {
  strings:
    $key_94a0 = { c3 d2 [2] f1 f0 [2] f7 c5 [2] d9 c5 [2] e6 d9 }

  condition:
    any of them
}