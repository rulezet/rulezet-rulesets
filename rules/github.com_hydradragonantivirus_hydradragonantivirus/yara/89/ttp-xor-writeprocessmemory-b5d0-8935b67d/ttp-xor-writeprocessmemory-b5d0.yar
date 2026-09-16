rule TTP_XOR_WriteProcessMemory_b5d0 {
  strings:
    $key_b5d0 = { e2 a2 [2] d0 80 [2] d6 b5 [2] f8 b5 [2] c7 a9 }

  condition:
    any of them
}