rule TTP_XOR_WriteProcessMemory_a433 {
  strings:
    $key_a433 = { f3 41 [2] c1 63 [2] c7 56 [2] e9 56 [2] d6 4a }

  condition:
    any of them
}