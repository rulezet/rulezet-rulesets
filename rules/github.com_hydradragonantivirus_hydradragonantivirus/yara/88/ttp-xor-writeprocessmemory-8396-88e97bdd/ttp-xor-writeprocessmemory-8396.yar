rule TTP_XOR_WriteProcessMemory_8396 {
  strings:
    $key_8396 = { d4 e4 [2] e6 c6 [2] e0 f3 [2] ce f3 [2] f1 ef }

  condition:
    any of them
}