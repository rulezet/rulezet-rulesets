rule TTP_XOR_WriteProcessMemory_a440 {
  strings:
    $key_a440 = { f3 32 [2] c1 10 [2] c7 25 [2] e9 25 [2] d6 39 }

  condition:
    any of them
}