rule TTP_XOR_WriteProcessMemory_a0f7 {
  strings:
    $key_a0f7 = { f7 85 [2] c5 a7 [2] c3 92 [2] ed 92 [2] d2 8e }

  condition:
    any of them
}