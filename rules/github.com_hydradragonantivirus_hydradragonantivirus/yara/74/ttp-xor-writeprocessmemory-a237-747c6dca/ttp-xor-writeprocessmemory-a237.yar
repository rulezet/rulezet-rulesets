rule TTP_XOR_WriteProcessMemory_a237 {
  strings:
    $key_a237 = { f5 45 [2] c7 67 [2] c1 52 [2] ef 52 [2] d0 4e }

  condition:
    any of them
}