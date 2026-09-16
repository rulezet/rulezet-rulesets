rule TTP_XOR_WriteProcessMemory_9d8a {
  strings:
    $key_9d8a = { ca f8 [2] f8 da [2] fe ef [2] d0 ef [2] ef f3 }

  condition:
    any of them
}