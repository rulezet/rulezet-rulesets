rule TTP_XOR_WriteProcessMemory_a443 {
  strings:
    $key_a443 = { f3 31 [2] c1 13 [2] c7 26 [2] e9 26 [2] d6 3a }

  condition:
    any of them
}