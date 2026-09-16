rule TTP_XOR_WriteProcessMemory_86f1 {
  strings:
    $key_86f1 = { d1 83 [2] e3 a1 [2] e5 94 [2] cb 94 [2] f4 88 }

  condition:
    any of them
}