rule TTP_XOR_WriteProcessMemory_a0d0 {
  strings:
    $key_a0d0 = { f7 a2 [2] c5 80 [2] c3 b5 [2] ed b5 [2] d2 a9 }

  condition:
    any of them
}