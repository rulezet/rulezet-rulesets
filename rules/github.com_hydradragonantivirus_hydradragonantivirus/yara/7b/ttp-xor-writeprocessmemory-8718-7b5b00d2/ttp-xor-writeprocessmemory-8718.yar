rule TTP_XOR_WriteProcessMemory_8718 {
  strings:
    $key_8718 = { d0 6a [2] e2 48 [2] e4 7d [2] ca 7d [2] f5 61 }

  condition:
    any of them
}