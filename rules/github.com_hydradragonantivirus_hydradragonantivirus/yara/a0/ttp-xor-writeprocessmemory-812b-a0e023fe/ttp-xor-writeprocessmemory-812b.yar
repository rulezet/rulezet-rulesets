rule TTP_XOR_WriteProcessMemory_812b {
  strings:
    $key_812b = { d6 59 [2] e4 7b [2] e2 4e [2] cc 4e [2] f3 52 }

  condition:
    any of them
}