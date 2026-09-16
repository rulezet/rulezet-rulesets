rule TTP_XOR_WriteProcessMemory_8602 {
  strings:
    $key_8602 = { d1 70 [2] e3 52 [2] e5 67 [2] cb 67 [2] f4 7b }

  condition:
    any of them
}