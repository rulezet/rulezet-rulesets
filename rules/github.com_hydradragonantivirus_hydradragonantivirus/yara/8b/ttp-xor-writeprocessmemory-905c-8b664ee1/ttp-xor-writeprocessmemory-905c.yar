rule TTP_XOR_WriteProcessMemory_905c {
  strings:
    $key_905c = { c7 2e [2] f5 0c [2] f3 39 [2] dd 39 [2] e2 25 }

  condition:
    any of them
}