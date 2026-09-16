rule TTP_XOR_WriteProcessMemory_860c {
  strings:
    $key_860c = { d1 7e [2] e3 5c [2] e5 69 [2] cb 69 [2] f4 75 }

  condition:
    any of them
}