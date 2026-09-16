rule TTP_XOR_WriteProcessMemory_a465 {
  strings:
    $key_a465 = { f3 17 [2] c1 35 [2] c7 00 [2] e9 00 [2] d6 1c }

  condition:
    any of them
}