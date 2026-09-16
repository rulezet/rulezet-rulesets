rule TTP_XOR_WriteProcessMemory_9c8b {
  strings:
    $key_9c8b = { cb f9 [2] f9 db [2] ff ee [2] d1 ee [2] ee f2 }

  condition:
    any of them
}