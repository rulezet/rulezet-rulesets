rule TTP_XOR_WriteProcessMemory_86f6 {
  strings:
    $key_86f6 = { d1 84 [2] e3 a6 [2] e5 93 [2] cb 93 [2] f4 8f }

  condition:
    any of them
}