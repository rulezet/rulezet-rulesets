rule TTP_XOR_WriteProcessMemory_870d {
  strings:
    $key_870d = { d0 7f [2] e2 5d [2] e4 68 [2] ca 68 [2] f5 74 }

  condition:
    any of them
}