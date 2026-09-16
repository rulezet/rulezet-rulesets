rule TTP_XOR_WriteProcessMemory_86f8 {
  strings:
    $key_86f8 = { d1 8a [2] e3 a8 [2] e5 9d [2] cb 9d [2] f4 81 }

  condition:
    any of them
}