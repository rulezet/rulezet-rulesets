rule TTP_XOR_WriteProcessMemory_a4f2 {
  strings:
    $key_a4f2 = { f3 80 [2] c1 a2 [2] c7 97 [2] e9 97 [2] d6 8b }

  condition:
    any of them
}