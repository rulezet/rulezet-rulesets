rule TTP_XOR_WriteProcessMemory_86e2 {
  strings:
    $key_86e2 = { d1 90 [2] e3 b2 [2] e5 87 [2] cb 87 [2] f4 9b }

  condition:
    any of them
}