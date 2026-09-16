rule TTP_XOR_WriteProcessMemory_9789 {
  strings:
    $key_9789 = { c0 fb [2] f2 d9 [2] f4 ec [2] da ec [2] e5 f0 }

  condition:
    any of them
}