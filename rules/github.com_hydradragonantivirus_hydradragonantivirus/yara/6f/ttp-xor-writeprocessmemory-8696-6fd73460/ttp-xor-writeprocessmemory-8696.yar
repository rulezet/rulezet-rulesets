rule TTP_XOR_WriteProcessMemory_8696 {
  strings:
    $key_8696 = { d1 e4 [2] e3 c6 [2] e5 f3 [2] cb f3 [2] f4 ef }

  condition:
    any of them
}