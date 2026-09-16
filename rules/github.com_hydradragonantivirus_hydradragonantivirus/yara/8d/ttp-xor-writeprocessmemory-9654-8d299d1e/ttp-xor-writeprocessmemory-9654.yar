rule TTP_XOR_WriteProcessMemory_9654 {
  strings:
    $key_9654 = { c1 26 [2] f3 04 [2] f5 31 [2] db 31 [2] e4 2d }

  condition:
    any of them
}