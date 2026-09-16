rule TTP_XOR_WriteProcessMemory_9c8c {
  strings:
    $key_9c8c = { cb fe [2] f9 dc [2] ff e9 [2] d1 e9 [2] ee f5 }

  condition:
    any of them
}