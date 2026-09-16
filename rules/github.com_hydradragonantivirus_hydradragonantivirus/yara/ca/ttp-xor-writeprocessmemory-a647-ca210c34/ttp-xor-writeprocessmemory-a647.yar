rule TTP_XOR_WriteProcessMemory_a647 {
  strings:
    $key_a647 = { f1 35 [2] c3 17 [2] c5 22 [2] eb 22 [2] d4 3e }

  condition:
    any of them
}