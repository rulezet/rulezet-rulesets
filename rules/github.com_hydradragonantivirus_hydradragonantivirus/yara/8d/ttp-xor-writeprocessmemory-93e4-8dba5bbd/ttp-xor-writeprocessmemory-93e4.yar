rule TTP_XOR_WriteProcessMemory_93e4 {
  strings:
    $key_93e4 = { c4 96 [2] f6 b4 [2] f0 81 [2] de 81 [2] e1 9d }

  condition:
    any of them
}