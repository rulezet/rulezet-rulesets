rule TTP_XOR_WriteProcessMemory_a461 {
  strings:
    $key_a461 = { f3 13 [2] c1 31 [2] c7 04 [2] e9 04 [2] d6 18 }

  condition:
    any of them
}