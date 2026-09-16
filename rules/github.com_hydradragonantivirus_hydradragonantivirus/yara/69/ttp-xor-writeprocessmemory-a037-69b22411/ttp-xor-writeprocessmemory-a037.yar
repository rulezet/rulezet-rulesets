rule TTP_XOR_WriteProcessMemory_a037 {
  strings:
    $key_a037 = { f7 45 [2] c5 67 [2] c3 52 [2] ed 52 [2] d2 4e }

  condition:
    any of them
}