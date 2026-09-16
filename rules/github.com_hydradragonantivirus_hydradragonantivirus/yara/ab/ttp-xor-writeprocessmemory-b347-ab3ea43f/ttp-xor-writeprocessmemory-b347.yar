rule TTP_XOR_WriteProcessMemory_b347 {
  strings:
    $key_b347 = { e4 35 [2] d6 17 [2] d0 22 [2] fe 22 [2] c1 3e }

  condition:
    any of them
}