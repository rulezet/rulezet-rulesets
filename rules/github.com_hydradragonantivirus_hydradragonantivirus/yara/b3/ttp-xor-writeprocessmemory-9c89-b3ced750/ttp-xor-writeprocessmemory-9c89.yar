rule TTP_XOR_WriteProcessMemory_9c89 {
  strings:
    $key_9c89 = { cb fb [2] f9 d9 [2] ff ec [2] d1 ec [2] ee f0 }

  condition:
    any of them
}