rule TTP_XOR_WriteProcessMemory_b475 {
  strings:
    $key_b475 = { e3 07 [2] d1 25 [2] d7 10 [2] f9 10 [2] c6 0c }

  condition:
    any of them
}