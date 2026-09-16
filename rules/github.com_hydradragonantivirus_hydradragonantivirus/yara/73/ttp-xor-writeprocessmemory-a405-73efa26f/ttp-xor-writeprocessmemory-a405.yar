rule TTP_XOR_WriteProcessMemory_a405 {
  strings:
    $key_a405 = { f3 77 [2] c1 55 [2] c7 60 [2] e9 60 [2] d6 7c }

  condition:
    any of them
}