rule TTP_XOR_WriteProcessMemory_a0c0 {
  strings:
    $key_a0c0 = { f7 b2 [2] c5 90 [2] c3 a5 [2] ed a5 [2] d2 b9 }

  condition:
    any of them
}