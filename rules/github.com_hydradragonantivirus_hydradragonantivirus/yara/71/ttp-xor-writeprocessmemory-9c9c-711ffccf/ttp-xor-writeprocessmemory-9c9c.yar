rule TTP_XOR_WriteProcessMemory_9c9c {
  strings:
    $key_9c9c = { cb ee [2] f9 cc [2] ff f9 [2] d1 f9 [2] ee e5 }

  condition:
    any of them
}