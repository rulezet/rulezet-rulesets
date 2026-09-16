rule TTP_XOR_WriteProcessMemory_8748 {
  strings:
    $key_8748 = { d0 3a [2] e2 18 [2] e4 2d [2] ca 2d [2] f5 31 }

  condition:
    any of them
}