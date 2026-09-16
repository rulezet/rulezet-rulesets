rule TTP_XOR_WriteProcessMemory_94f0 {
  strings:
    $key_94f0 = { c3 82 [2] f1 a0 [2] f7 95 [2] d9 95 [2] e6 89 }

  condition:
    any of them
}