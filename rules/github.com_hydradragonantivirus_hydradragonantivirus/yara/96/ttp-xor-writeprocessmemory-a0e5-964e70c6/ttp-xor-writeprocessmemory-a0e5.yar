rule TTP_XOR_WriteProcessMemory_a0e5 {
  strings:
    $key_a0e5 = { f7 97 [2] c5 b5 [2] c3 80 [2] ed 80 [2] d2 9c }

  condition:
    any of them
}