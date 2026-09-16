rule TTP_XOR_WriteProcessMemory_9652 {
  strings:
    $key_9652 = { c1 20 [2] f3 02 [2] f5 37 [2] db 37 [2] e4 2b }

  condition:
    any of them
}