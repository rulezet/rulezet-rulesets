rule TTP_XOR_WriteProcessMemory_9038 {
  strings:
    $key_9038 = { c7 4a [2] f5 68 [2] f3 5d [2] dd 5d [2] e2 41 }

  condition:
    any of them
}