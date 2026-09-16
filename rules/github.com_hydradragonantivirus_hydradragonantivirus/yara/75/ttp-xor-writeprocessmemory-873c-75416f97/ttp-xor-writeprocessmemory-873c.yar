rule TTP_XOR_WriteProcessMemory_873c {
  strings:
    $key_873c = { d0 4e [2] e2 6c [2] e4 59 [2] ca 59 [2] f5 45 }

  condition:
    any of them
}