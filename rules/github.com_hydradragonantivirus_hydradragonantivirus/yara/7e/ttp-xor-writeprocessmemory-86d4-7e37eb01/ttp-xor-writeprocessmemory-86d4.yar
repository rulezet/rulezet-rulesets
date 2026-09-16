rule TTP_XOR_WriteProcessMemory_86d4 {
  strings:
    $key_86d4 = { d1 a6 [2] e3 84 [2] e5 b1 [2] cb b1 [2] f4 ad }

  condition:
    any of them
}