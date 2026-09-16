rule TTP_XOR_WriteProcessMemory_8640 {
  strings:
    $key_8640 = { d1 32 [2] e3 10 [2] e5 25 [2] cb 25 [2] f4 39 }

  condition:
    any of them
}