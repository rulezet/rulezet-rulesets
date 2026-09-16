rule TTP_XOR_WriteProcessMemory_8632 {
  strings:
    $key_8632 = { d1 40 [2] e3 62 [2] e5 57 [2] cb 57 [2] f4 4b }

  condition:
    any of them
}