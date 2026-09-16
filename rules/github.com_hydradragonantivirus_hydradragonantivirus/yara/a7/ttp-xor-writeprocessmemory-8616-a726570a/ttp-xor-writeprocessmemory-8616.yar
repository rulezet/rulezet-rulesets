rule TTP_XOR_WriteProcessMemory_8616 {
  strings:
    $key_8616 = { d1 64 [2] e3 46 [2] e5 73 [2] cb 73 [2] f4 6f }

  condition:
    any of them
}