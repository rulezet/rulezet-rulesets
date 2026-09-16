rule TTP_XOR_WriteProcessMemory_86b0 {
  strings:
    $key_86b0 = { d1 c2 [2] e3 e0 [2] e5 d5 [2] cb d5 [2] f4 c9 }

  condition:
    any of them
}