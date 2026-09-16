rule TTP_XOR_WriteProcessMemory_b4e5 {
  strings:
    $key_b4e5 = { e3 97 [2] d1 b5 [2] d7 80 [2] f9 80 [2] c6 9c }

  condition:
    any of them
}