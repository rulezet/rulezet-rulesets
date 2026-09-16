rule TTP_XOR_WriteProcessMemory_9559 {
  strings:
    $key_9559 = { c2 2b [2] f0 09 [2] f6 3c [2] d8 3c [2] e7 20 }

  condition:
    any of them
}