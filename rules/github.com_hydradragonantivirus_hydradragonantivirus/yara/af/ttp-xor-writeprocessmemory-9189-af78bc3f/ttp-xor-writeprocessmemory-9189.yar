rule TTP_XOR_WriteProcessMemory_9189 {
  strings:
    $key_9189 = { c6 fb [2] f4 d9 [2] f2 ec [2] dc ec [2] e3 f0 }

  condition:
    any of them
}