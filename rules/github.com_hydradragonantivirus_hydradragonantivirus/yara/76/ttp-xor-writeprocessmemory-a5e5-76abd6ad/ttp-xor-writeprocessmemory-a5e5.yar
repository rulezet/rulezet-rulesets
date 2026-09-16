rule TTP_XOR_WriteProcessMemory_a5e5 {
  strings:
    $key_a5e5 = { f2 97 [2] c0 b5 [2] c6 80 [2] e8 80 [2] d7 9c }

  condition:
    any of them
}