rule TTP_XOR_WriteProcessMemory_9ca0 {
  strings:
    $key_9ca0 = { cb d2 [2] f9 f0 [2] ff c5 [2] d1 c5 [2] ee d9 }

  condition:
    any of them
}