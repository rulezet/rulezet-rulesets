rule TTP_XOR_WriteProcessMemory_82e4 {
  strings:
    $key_82e4 = { d5 96 [2] e7 b4 [2] e1 81 [2] cf 81 [2] f0 9d }

  condition:
    any of them
}