rule TTP_XOR_WriteProcessMemory_a579 {
  strings:
    $key_a579 = { f2 0b [2] c0 29 [2] c6 1c [2] e8 1c [2] d7 00 }

  condition:
    any of them
}