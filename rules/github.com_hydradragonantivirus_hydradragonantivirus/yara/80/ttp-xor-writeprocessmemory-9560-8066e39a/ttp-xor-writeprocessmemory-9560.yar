rule TTP_XOR_WriteProcessMemory_9560 {
  strings:
    $key_9560 = { c2 12 [2] f0 30 [2] f6 05 [2] d8 05 [2] e7 19 }

  condition:
    any of them
}