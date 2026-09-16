rule TTP_XOR_WriteProcessMemory_9d91 {
  strings:
    $key_9d91 = { ca e3 [2] f8 c1 [2] fe f4 [2] d0 f4 [2] ef e8 }

  condition:
    any of them
}