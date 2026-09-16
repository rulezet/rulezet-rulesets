rule TTP_XOR_WriteProcessMemory_a402 {
  strings:
    $key_a402 = { f3 70 [2] c1 52 [2] c7 67 [2] e9 67 [2] d6 7b }

  condition:
    any of them
}