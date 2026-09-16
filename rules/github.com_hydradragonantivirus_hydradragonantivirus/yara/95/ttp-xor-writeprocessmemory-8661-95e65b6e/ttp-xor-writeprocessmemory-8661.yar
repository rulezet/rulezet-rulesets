rule TTP_XOR_WriteProcessMemory_8661 {
  strings:
    $key_8661 = { d1 13 [2] e3 31 [2] e5 04 [2] cb 04 [2] f4 18 }

  condition:
    any of them
}