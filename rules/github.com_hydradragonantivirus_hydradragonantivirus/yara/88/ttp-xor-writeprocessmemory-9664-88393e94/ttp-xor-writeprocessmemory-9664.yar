rule TTP_XOR_WriteProcessMemory_9664 {
  strings:
    $key_9664 = { c1 16 [2] f3 34 [2] f5 01 [2] db 01 [2] e4 1d }

  condition:
    any of them
}