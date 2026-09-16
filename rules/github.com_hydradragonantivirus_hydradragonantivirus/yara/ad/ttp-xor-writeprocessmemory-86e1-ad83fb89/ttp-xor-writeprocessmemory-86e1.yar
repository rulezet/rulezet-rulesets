rule TTP_XOR_WriteProcessMemory_86e1 {
  strings:
    $key_86e1 = { d1 93 [2] e3 b1 [2] e5 84 [2] cb 84 [2] f4 98 }

  condition:
    any of them
}