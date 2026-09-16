rule TTP_XOR_WriteProcessMemory_a537 {
  strings:
    $key_a537 = { f2 45 [2] c0 67 [2] c6 52 [2] e8 52 [2] d7 4e }

  condition:
    any of them
}