rule TTP_XOR_WriteProcessMemory_8644 {
  strings:
    $key_8644 = { d1 36 [2] e3 14 [2] e5 21 [2] cb 21 [2] f4 3d }

  condition:
    any of them
}