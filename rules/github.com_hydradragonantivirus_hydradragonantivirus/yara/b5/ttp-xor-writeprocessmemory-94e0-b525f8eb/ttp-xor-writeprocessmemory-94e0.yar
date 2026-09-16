rule TTP_XOR_WriteProcessMemory_94e0 {
  strings:
    $key_94e0 = { c3 92 [2] f1 b0 [2] f7 85 [2] d9 85 [2] e6 99 }

  condition:
    any of them
}