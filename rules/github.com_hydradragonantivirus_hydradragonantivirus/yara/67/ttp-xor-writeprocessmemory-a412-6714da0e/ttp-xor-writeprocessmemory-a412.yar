rule TTP_XOR_WriteProcessMemory_a412 {
  strings:
    $key_a412 = { f3 60 [2] c1 42 [2] c7 77 [2] e9 77 [2] d6 6b }

  condition:
    any of them
}