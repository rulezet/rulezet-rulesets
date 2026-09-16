rule TTP_XOR_WriteProcessMemory_807c {
  strings:
    $key_807c = { d7 0e [2] e5 2c [2] e3 19 [2] cd 19 [2] f2 05 }

  condition:
    any of them
}