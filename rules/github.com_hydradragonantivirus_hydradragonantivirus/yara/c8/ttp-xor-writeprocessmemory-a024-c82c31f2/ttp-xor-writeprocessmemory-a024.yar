rule TTP_XOR_WriteProcessMemory_a024 {
  strings:
    $key_a024 = { f7 56 [2] c5 74 [2] c3 41 [2] ed 41 [2] d2 5d }

  condition:
    any of them
}