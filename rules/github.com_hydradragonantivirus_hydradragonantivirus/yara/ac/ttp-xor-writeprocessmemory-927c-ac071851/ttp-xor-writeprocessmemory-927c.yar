rule TTP_XOR_WriteProcessMemory_927c {
  strings:
    $key_927c = { c5 0e [2] f7 2c [2] f1 19 [2] df 19 [2] e0 05 }

  condition:
    any of them
}