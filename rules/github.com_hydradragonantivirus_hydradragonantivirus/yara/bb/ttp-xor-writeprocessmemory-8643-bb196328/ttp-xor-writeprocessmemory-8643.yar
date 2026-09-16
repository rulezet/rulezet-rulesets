rule TTP_XOR_WriteProcessMemory_8643 {
  strings:
    $key_8643 = { d1 31 [2] e3 13 [2] e5 26 [2] cb 26 [2] f4 3a }

  condition:
    any of them
}