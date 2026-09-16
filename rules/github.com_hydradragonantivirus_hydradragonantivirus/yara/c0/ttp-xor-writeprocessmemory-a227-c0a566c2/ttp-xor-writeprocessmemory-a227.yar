rule TTP_XOR_WriteProcessMemory_a227 {
  strings:
    $key_a227 = { f5 55 [2] c7 77 [2] c1 42 [2] ef 42 [2] d0 5e }

  condition:
    any of them
}