rule TTP_XOR_WriteProcessMemory_867c {
  strings:
    $key_867c = { d1 0e [2] e3 2c [2] e5 19 [2] cb 19 [2] f4 05 }

  condition:
    any of them
}