rule TTP_XOR_WriteProcessMemory_a725 {
  strings:
    $key_a725 = { f0 57 [2] c2 75 [2] c4 40 [2] ea 40 [2] d5 5c }

  condition:
    any of them
}