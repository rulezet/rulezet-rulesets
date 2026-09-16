rule TTP_XOR_WriteProcessMemory_b5f5 {
  strings:
    $key_b5f5 = { e2 87 [2] d0 a5 [2] d6 90 [2] f8 90 [2] c7 8c }

  condition:
    any of them
}