rule TTP_XOR_WriteProcessMemory_94e1 {
  strings:
    $key_94e1 = { c3 93 [2] f1 b1 [2] f7 84 [2] d9 84 [2] e6 98 }

  condition:
    any of them
}