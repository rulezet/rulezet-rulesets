rule TTP_XOR_WriteProcessMemory_a275 {
  strings:
    $key_a275 = { f5 07 [2] c7 25 [2] c1 10 [2] ef 10 [2] d0 0c }

  condition:
    any of them
}