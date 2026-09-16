rule TTP_XOR_WriteProcessMemory_b493 {
  strings:
    $key_b493 = { e3 e1 [2] d1 c3 [2] d7 f6 [2] f9 f6 [2] c6 ea }

  condition:
    any of them
}