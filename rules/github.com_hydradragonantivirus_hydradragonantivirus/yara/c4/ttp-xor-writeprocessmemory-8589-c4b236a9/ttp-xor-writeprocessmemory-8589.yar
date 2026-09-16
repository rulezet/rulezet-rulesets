rule TTP_XOR_WriteProcessMemory_8589 {
  strings:
    $key_8589 = { d2 fb [2] e0 d9 [2] e6 ec [2] c8 ec [2] f7 f0 }

  condition:
    any of them
}