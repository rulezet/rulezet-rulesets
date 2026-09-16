rule TTP_XOR_WriteProcessMemory_9667 {
  strings:
    $key_9667 = { c1 15 [2] f3 37 [2] f5 02 [2] db 02 [2] e4 1e }

  condition:
    any of them
}