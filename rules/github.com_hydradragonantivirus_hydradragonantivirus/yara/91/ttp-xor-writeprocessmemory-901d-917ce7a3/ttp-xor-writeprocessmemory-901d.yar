rule TTP_XOR_WriteProcessMemory_901d {
  strings:
    $key_901d = { c7 6f [2] f5 4d [2] f3 78 [2] dd 78 [2] e2 64 }

  condition:
    any of them
}