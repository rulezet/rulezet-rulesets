rule TTP_XOR_WriteProcessMemory_86b4 {
  strings:
    $key_86b4 = { d1 c6 [2] e3 e4 [2] e5 d1 [2] cb d1 [2] f4 cd }

  condition:
    any of them
}