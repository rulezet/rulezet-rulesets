rule TTP_XOR_WriteProcessMemory_927e {
  strings:
    $key_927e = { c5 0c [2] f7 2e [2] f1 1b [2] df 1b [2] e0 07 }

  condition:
    any of them
}