rule TTP_XOR_WriteProcessMemory_9258 {
  strings:
    $key_9258 = { c5 2a [2] f7 08 [2] f1 3d [2] df 3d [2] e0 21 }

  condition:
    any of them
}