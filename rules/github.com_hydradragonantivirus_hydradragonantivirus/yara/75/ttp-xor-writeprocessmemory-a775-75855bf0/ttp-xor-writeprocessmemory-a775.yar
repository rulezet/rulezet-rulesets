rule TTP_XOR_WriteProcessMemory_a775 {
  strings:
    $key_a775 = { f0 07 [2] c2 25 [2] c4 10 [2] ea 10 [2] d5 0c }

  condition:
    any of them
}