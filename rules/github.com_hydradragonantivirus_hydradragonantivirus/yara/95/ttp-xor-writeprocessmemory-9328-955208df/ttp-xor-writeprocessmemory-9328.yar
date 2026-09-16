rule TTP_XOR_WriteProcessMemory_9328 {
  strings:
    $key_9328 = { c4 5a [2] f6 78 [2] f0 4d [2] de 4d [2] e1 51 }

  condition:
    any of them
}