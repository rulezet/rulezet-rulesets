rule TTP_XOR_WriteProcessMemory_871e {
  strings:
    $key_871e = { d0 6c [2] e2 4e [2] e4 7b [2] ca 7b [2] f5 67 }

  condition:
    any of them
}