rule TTP_XOR_WriteProcessMemory_901b {
  strings:
    $key_901b = { c7 69 [2] f5 4b [2] f3 7e [2] dd 7e [2] e2 62 }

  condition:
    any of them
}