rule TTP_XOR_WriteProcessMemory_8678 {
  strings:
    $key_8678 = { d1 0a [2] e3 28 [2] e5 1d [2] cb 1d [2] f4 01 }

  condition:
    any of them
}