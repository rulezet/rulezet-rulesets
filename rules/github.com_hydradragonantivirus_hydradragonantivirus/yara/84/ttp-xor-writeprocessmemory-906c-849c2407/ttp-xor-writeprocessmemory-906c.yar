rule TTP_XOR_WriteProcessMemory_906c {
  strings:
    $key_906c = { c7 1e [2] f5 3c [2] f3 09 [2] dd 09 [2] e2 15 }

  condition:
    any of them
}