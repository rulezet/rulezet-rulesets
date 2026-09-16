rule TTP_XOR_WriteProcessMemory_83c4 {
  strings:
    $key_83c4 = { d4 b6 [2] e6 94 [2] e0 a1 [2] ce a1 [2] f1 bd }

  condition:
    any of them
}