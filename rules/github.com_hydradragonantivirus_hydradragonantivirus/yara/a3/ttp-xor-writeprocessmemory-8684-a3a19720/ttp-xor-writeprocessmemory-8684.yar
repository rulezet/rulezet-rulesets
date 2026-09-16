rule TTP_XOR_WriteProcessMemory_8684 {
  strings:
    $key_8684 = { d1 f6 [2] e3 d4 [2] e5 e1 [2] cb e1 [2] f4 fd }

  condition:
    any of them
}