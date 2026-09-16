rule TTP_XOR_WriteProcessMemory_877d {
  strings:
    $key_877d = { d0 0f [2] e2 2d [2] e4 18 [2] ca 18 [2] f5 04 }

  condition:
    any of them
}