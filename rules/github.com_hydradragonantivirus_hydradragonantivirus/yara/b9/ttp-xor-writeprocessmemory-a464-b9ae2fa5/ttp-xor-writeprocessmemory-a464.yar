rule TTP_XOR_WriteProcessMemory_a464 {
  strings:
    $key_a464 = { f3 16 [2] c1 34 [2] c7 01 [2] e9 01 [2] d6 1d }

  condition:
    any of them
}