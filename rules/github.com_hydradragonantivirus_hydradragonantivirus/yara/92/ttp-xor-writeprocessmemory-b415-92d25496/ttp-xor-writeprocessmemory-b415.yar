rule TTP_XOR_WriteProcessMemory_b415 {
  strings:
    $key_b415 = { e3 67 [2] d1 45 [2] d7 70 [2] f9 70 [2] c6 6c }

  condition:
    any of them
}