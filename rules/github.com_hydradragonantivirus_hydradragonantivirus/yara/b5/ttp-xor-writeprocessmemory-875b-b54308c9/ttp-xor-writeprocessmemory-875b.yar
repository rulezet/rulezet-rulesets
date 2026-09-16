rule TTP_XOR_WriteProcessMemory_875b {
  strings:
    $key_875b = { d0 29 [2] e2 0b [2] e4 3e [2] ca 3e [2] f5 22 }

  condition:
    any of them
}