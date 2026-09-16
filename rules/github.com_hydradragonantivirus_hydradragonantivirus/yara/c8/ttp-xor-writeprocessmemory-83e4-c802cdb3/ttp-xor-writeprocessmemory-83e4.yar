rule TTP_XOR_WriteProcessMemory_83e4 {
  strings:
    $key_83e4 = { d4 96 [2] e6 b4 [2] e0 81 [2] ce 81 [2] f1 9d }

  condition:
    any of them
}