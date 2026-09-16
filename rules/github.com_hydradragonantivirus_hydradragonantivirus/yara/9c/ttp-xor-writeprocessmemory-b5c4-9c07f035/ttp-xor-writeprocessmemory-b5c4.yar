rule TTP_XOR_WriteProcessMemory_b5c4 {
  strings:
    $key_b5c4 = { e2 b6 [2] d0 94 [2] d6 a1 [2] f8 a1 [2] c7 bd }

  condition:
    any of them
}