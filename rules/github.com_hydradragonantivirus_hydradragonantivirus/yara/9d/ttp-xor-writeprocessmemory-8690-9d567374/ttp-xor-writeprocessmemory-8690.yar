rule TTP_XOR_WriteProcessMemory_8690 {
  strings:
    $key_8690 = { d1 e2 [2] e3 c0 [2] e5 f5 [2] cb f5 [2] f4 e9 }

  condition:
    any of them
}