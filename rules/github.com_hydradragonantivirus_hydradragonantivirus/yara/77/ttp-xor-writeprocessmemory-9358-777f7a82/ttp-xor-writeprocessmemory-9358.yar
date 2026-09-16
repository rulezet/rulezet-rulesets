rule TTP_XOR_WriteProcessMemory_9358 {
  strings:
    $key_9358 = { c4 2a [2] f6 08 [2] f0 3d [2] de 3d [2] e1 21 }

  condition:
    any of them
}