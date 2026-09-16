rule TTP_XOR_WriteProcessMemory_878a {
  strings:
    $key_878a = { d0 f8 [2] e2 da [2] e4 ef [2] ca ef [2] f5 f3 }

  condition:
    any of them
}