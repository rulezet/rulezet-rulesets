rule TTP_XOR_WriteProcessMemory_9638 {
  strings:
    $key_9638 = { c1 4a [2] f3 68 [2] f5 5d [2] db 5d [2] e4 41 }

  condition:
    any of them
}