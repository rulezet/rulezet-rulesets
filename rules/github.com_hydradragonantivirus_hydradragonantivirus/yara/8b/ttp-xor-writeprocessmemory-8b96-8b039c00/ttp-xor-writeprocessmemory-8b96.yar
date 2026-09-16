rule TTP_XOR_WriteProcessMemory_8b96 {
  strings:
    $key_8b96 = { dc e4 [2] ee c6 [2] e8 f3 [2] c6 f3 [2] f9 ef }

  condition:
    any of them
}