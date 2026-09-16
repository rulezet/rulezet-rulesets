rule TTP_XOR_WriteProcessMemory_8729 {
  strings:
    $key_8729 = { d0 5b [2] e2 79 [2] e4 4c [2] ca 4c [2] f5 50 }

  condition:
    any of them
}