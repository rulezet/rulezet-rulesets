rule TTP_XOR_WriteProcessMemory_9570 {
  strings:
    $key_9570 = { c2 02 [2] f0 20 [2] f6 15 [2] d8 15 [2] e7 09 }

  condition:
    any of them
}