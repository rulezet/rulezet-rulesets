rule TTP_XOR_WriteProcessMemory_b414 {
  strings:
    $key_b414 = { e3 66 [2] d1 44 [2] d7 71 [2] f9 71 [2] c6 6d }

  condition:
    any of them
}