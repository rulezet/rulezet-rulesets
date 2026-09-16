rule TTP_XOR_WriteProcessMemory_8648 {
  strings:
    $key_8648 = { d1 3a [2] e3 18 [2] e5 2d [2] cb 2d [2] f4 31 }

  condition:
    any of them
}