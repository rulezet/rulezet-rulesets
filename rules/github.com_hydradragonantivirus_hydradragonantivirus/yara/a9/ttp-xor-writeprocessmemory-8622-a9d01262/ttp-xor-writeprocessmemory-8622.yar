rule TTP_XOR_WriteProcessMemory_8622 {
  strings:
    $key_8622 = { d1 50 [2] e3 72 [2] e5 47 [2] cb 47 [2] f4 5b }

  condition:
    any of them
}