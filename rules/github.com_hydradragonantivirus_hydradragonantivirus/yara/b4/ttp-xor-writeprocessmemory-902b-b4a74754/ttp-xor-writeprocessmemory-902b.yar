rule TTP_XOR_WriteProcessMemory_902b {
  strings:
    $key_902b = { c7 59 [2] f5 7b [2] f3 4e [2] dd 4e [2] e2 52 }

  condition:
    any of them
}