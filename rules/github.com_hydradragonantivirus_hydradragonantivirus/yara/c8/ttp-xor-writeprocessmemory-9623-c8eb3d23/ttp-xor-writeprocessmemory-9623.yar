rule TTP_XOR_WriteProcessMemory_9623 {
  strings:
    $key_9623 = { c1 51 [2] f3 73 [2] f5 46 [2] db 46 [2] e4 5a }

  condition:
    any of them
}