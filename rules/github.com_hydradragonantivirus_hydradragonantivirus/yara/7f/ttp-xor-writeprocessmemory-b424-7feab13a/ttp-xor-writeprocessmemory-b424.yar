rule TTP_XOR_WriteProcessMemory_b424 {
  strings:
    $key_b424 = { e3 56 [2] d1 74 [2] d7 41 [2] f9 41 [2] c6 5d }

  condition:
    any of them
}