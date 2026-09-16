rule TTP_XOR_WriteProcessMemory_b312 {
  strings:
    $key_b312 = { e4 60 [2] d6 42 [2] d0 77 [2] fe 77 [2] c1 6b }

  condition:
    any of them
}