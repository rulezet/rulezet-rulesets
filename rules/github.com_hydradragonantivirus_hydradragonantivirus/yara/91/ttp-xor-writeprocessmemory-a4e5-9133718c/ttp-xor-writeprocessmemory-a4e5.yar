rule TTP_XOR_WriteProcessMemory_a4e5 {
  strings:
    $key_a4e5 = { f3 97 [2] c1 b5 [2] c7 80 [2] e9 80 [2] d6 9c }

  condition:
    any of them
}