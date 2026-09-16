rule TTP_XOR_WriteProcessMemory_8680 {
  strings:
    $key_8680 = { d1 f2 [2] e3 d0 [2] e5 e5 [2] cb e5 [2] f4 f9 }

  condition:
    any of them
}