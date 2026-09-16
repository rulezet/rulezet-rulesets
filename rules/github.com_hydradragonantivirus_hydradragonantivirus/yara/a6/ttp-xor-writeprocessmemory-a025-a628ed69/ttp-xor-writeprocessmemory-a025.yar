rule TTP_XOR_WriteProcessMemory_a025 {
  strings:
    $key_a025 = { f7 57 [2] c5 75 [2] c3 40 [2] ed 40 [2] d2 5c }

  condition:
    any of them
}