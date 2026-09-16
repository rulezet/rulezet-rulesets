rule TTP_XOR_WriteProcessMemory_8628 {
  strings:
    $key_8628 = { d1 5a [2] e3 78 [2] e5 4d [2] cb 4d [2] f4 51 }

  condition:
    any of them
}