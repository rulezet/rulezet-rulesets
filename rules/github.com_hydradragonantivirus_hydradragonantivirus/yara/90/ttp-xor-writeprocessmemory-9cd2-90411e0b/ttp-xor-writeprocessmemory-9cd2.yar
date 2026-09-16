rule TTP_XOR_WriteProcessMemory_9cd2 {
  strings:
    $key_9cd2 = { cb a0 [2] f9 82 [2] ff b7 [2] d1 b7 [2] ee ab }

  condition:
    any of them
}