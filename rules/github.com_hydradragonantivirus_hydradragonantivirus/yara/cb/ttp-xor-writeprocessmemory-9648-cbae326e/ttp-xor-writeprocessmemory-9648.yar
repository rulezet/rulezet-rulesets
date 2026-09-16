rule TTP_XOR_WriteProcessMemory_9648 {
  strings:
    $key_9648 = { c1 3a [2] f3 18 [2] f5 2d [2] db 2d [2] e4 31 }

  condition:
    any of them
}