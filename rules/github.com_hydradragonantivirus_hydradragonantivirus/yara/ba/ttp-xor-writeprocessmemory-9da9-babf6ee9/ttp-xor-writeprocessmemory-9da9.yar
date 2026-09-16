rule TTP_XOR_WriteProcessMemory_9da9 {
  strings:
    $key_9da9 = { ca db [2] f8 f9 [2] fe cc [2] d0 cc [2] ef d0 }

  condition:
    any of them
}