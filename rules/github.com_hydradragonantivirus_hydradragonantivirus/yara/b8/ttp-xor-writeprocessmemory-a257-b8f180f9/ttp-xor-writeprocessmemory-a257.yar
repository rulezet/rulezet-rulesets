rule TTP_XOR_WriteProcessMemory_a257 {
  strings:
    $key_a257 = { f5 25 [2] c7 07 [2] c1 32 [2] ef 32 [2] d0 2e }

  condition:
    any of them
}