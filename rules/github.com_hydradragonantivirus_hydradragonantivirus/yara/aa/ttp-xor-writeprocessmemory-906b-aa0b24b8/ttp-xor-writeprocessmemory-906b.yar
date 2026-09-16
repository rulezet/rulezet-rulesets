rule TTP_XOR_WriteProcessMemory_906b {
  strings:
    $key_906b = { c7 19 [2] f5 3b [2] f3 0e [2] dd 0e [2] e2 12 }

  condition:
    any of them
}