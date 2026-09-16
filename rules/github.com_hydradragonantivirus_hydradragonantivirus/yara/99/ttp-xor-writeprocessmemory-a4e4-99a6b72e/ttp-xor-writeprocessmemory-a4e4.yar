rule TTP_XOR_WriteProcessMemory_a4e4 {
  strings:
    $key_a4e4 = { f3 96 [2] c1 b4 [2] c7 81 [2] e9 81 [2] d6 9d }

  condition:
    any of them
}