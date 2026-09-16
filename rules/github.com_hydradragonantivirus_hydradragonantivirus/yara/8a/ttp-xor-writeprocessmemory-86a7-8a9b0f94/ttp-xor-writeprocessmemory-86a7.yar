rule TTP_XOR_WriteProcessMemory_86a7 {
  strings:
    $key_86a7 = { d1 d5 [2] e3 f7 [2] e5 c2 [2] cb c2 [2] f4 de }

  condition:
    any of them
}