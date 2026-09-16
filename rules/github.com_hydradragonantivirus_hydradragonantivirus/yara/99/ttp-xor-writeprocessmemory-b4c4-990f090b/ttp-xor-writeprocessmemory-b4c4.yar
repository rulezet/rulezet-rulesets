rule TTP_XOR_WriteProcessMemory_b4c4 {
  strings:
    $key_b4c4 = { e3 b6 [2] d1 94 [2] d7 a1 [2] f9 a1 [2] c6 bd }

  condition:
    any of them
}