rule TTP_XOR_WriteProcessMemory_875d {
  strings:
    $key_875d = { d0 2f [2] e2 0d [2] e4 38 [2] ca 38 [2] f5 24 }

  condition:
    any of them
}