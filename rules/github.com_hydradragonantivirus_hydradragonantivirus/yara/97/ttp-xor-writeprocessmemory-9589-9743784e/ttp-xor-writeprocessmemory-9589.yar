rule TTP_XOR_WriteProcessMemory_9589 {
  strings:
    $key_9589 = { c2 fb [2] f0 d9 [2] f6 ec [2] d8 ec [2] e7 f0 }

  condition:
    any of them
}