rule TTP_XOR_WriteProcessMemory_a050 {
  strings:
    $key_a050 = { f7 22 [2] c5 00 [2] c3 35 [2] ed 35 [2] d2 29 }

  condition:
    any of them
}