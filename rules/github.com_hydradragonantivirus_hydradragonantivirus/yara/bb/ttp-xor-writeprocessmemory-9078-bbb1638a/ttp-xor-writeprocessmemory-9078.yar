rule TTP_XOR_WriteProcessMemory_9078 {
  strings:
    $key_9078 = { c7 0a [2] f5 28 [2] f3 1d [2] dd 1d [2] e2 01 }

  condition:
    any of them
}