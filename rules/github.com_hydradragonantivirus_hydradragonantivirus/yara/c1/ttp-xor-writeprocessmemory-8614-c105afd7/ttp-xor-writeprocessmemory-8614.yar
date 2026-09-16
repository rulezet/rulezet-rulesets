rule TTP_XOR_WriteProcessMemory_8614 {
  strings:
    $key_8614 = { d1 66 [2] e3 44 [2] e5 71 [2] cb 71 [2] f4 6d }

  condition:
    any of them
}