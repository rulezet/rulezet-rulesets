rule TTP_XOR_WriteProcessMemory_856b {
  strings:
    $key_856b = { d2 19 [2] e0 3b [2] e6 0e [2] c8 0e [2] f7 12 }

  condition:
    any of them
}