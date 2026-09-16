rule TTP_XOR_WriteProcessMemory_a4f7 {
  strings:
    $key_a4f7 = { f3 85 [2] c1 a7 [2] c7 92 [2] e9 92 [2] d6 8e }

  condition:
    any of them
}