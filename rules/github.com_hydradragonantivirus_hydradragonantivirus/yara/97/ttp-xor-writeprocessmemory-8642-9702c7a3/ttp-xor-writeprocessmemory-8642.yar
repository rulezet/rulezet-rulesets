rule TTP_XOR_WriteProcessMemory_8642 {
  strings:
    $key_8642 = { d1 30 [2] e3 12 [2] e5 27 [2] cb 27 [2] f4 3b }

  condition:
    any of them
}