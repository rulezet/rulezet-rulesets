rule TTP_XOR_WriteProcessMemory_a473 {
  strings:
    $key_a473 = { f3 01 [2] c1 23 [2] c7 16 [2] e9 16 [2] d6 0a }

  condition:
    any of them
}