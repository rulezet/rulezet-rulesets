rule TTP_XOR_WriteProcessMemory_8600 {
  strings:
    $key_8600 = { d1 72 [2] e3 50 [2] e5 65 [2] cb 65 [2] f4 79 }

  condition:
    any of them
}