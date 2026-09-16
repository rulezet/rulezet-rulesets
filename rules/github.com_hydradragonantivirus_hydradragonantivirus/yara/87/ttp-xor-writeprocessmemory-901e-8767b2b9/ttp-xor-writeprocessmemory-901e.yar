rule TTP_XOR_WriteProcessMemory_901e {
  strings:
    $key_901e = { c7 6c [2] f5 4e [2] f3 7b [2] dd 7b [2] e2 67 }

  condition:
    any of them
}