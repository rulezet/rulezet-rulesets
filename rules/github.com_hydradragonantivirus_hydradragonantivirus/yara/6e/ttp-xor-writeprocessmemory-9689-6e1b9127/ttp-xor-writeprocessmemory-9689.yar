rule TTP_XOR_WriteProcessMemory_9689 {
  strings:
    $key_9689 = { c1 fb [2] f3 d9 [2] f5 ec [2] db ec [2] e4 f0 }

  condition:
    any of them
}