rule TTP_XOR_WriteProcessMemory_a512 {
  strings:
    $key_a512 = { f2 60 [2] c0 42 [2] c6 77 [2] e8 77 [2] d7 6b }

  condition:
    any of them
}