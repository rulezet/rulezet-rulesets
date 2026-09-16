rule TTP_XOR_WriteProcessMemory_a452 {
  strings:
    $key_a452 = { f3 20 [2] c1 02 [2] c7 37 [2] e9 37 [2] d6 2b }

  condition:
    any of them
}