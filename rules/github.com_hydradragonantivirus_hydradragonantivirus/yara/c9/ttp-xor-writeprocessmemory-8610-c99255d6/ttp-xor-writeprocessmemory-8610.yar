rule TTP_XOR_WriteProcessMemory_8610 {
  strings:
    $key_8610 = { d1 62 [2] e3 40 [2] e5 75 [2] cb 75 [2] f4 69 }

  condition:
    any of them
}