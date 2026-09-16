rule TTP_XOR_WriteProcessMemory_94e6 {
  strings:
    $key_94e6 = { c3 94 [2] f1 b6 [2] f7 83 [2] d9 83 [2] e6 9f }

  condition:
    any of them
}