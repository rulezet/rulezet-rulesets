rule TTP_XOR_WriteProcessMemory_8651 {
  strings:
    $key_8651 = { d1 23 [2] e3 01 [2] e5 34 [2] cb 34 [2] f4 28 }

  condition:
    any of them
}