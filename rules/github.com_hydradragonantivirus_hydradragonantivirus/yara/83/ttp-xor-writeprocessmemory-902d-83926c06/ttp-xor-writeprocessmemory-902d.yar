rule TTP_XOR_WriteProcessMemory_902d {
  strings:
    $key_902d = { c7 5f [2] f5 7d [2] f3 48 [2] dd 48 [2] e2 54 }

  condition:
    any of them
}