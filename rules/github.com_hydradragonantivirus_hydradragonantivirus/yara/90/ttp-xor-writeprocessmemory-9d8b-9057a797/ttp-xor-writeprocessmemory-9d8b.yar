rule TTP_XOR_WriteProcessMemory_9d8b {
  strings:
    $key_9d8b = { ca f9 [2] f8 db [2] fe ee [2] d0 ee [2] ef f2 }

  condition:
    any of them
}