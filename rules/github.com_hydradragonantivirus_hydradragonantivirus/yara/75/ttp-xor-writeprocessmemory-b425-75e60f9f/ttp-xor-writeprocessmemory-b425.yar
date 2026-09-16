rule TTP_XOR_WriteProcessMemory_b425 {
  strings:
    $key_b425 = { e3 57 [2] d1 75 [2] d7 40 [2] f9 40 [2] c6 5c }

  condition:
    any of them
}