rule TTP_XOR_WriteProcessMemory_a027 {
  strings:
    $key_a027 = { f7 55 [2] c5 77 [2] c3 42 [2] ed 42 [2] d2 5e }

  condition:
    any of them
}