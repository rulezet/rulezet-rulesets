rule TTP_XOR_WriteProcessMemory_871c {
  strings:
    $key_871c = { d0 6e [2] e2 4c [2] e4 79 [2] ca 79 [2] f5 65 }

  condition:
    any of them
}