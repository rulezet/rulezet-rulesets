rule TTP_XOR_WriteProcessMemory_94e4 {
  strings:
    $key_94e4 = { c3 96 [2] f1 b4 [2] f7 81 [2] d9 81 [2] e6 9d }

  condition:
    any of them
}