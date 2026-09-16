rule TTP_XOR_WriteProcessMemory_9089 {
  strings:
    $key_9089 = { c7 fb [2] f5 d9 [2] f3 ec [2] dd ec [2] e2 f0 }

  condition:
    any of them
}