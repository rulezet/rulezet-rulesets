rule TTP_XOR_WriteProcessMemory_874d {
  strings:
    $key_874d = { d0 3f [2] e2 1d [2] e4 28 [2] ca 28 [2] f5 34 }

  condition:
    any of them
}