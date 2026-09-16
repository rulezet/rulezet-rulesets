rule TTP_XOR_WriteProcessMemory_9611 {
  strings:
    $key_9611 = { c1 63 [2] f3 41 [2] f5 74 [2] db 74 [2] e4 68 }

  condition:
    any of them
}