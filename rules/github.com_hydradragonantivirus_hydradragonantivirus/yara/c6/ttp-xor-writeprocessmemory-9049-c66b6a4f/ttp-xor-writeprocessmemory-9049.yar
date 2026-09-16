rule TTP_XOR_WriteProcessMemory_9049 {
  strings:
    $key_9049 = { c7 3b [2] f5 19 [2] f3 2c [2] dd 2c [2] e2 30 }

  condition:
    any of them
}