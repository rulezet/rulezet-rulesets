rule TTP_XOR_WriteProcessMemory_b591 {
  strings:
    $key_b591 = { e2 e3 [2] d0 c1 [2] d6 f4 [2] f8 f4 [2] c7 e8 }

  condition:
    any of them
}