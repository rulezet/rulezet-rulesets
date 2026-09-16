rule TTP_XOR_WriteProcessMemory_86b9 {
  strings:
    $key_86b9 = { d1 cb [2] e3 e9 [2] e5 dc [2] cb dc [2] f4 c0 }

  condition:
    any of them
}