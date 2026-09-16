rule TTP_XOR_WriteProcessMemory_9dda {
  strings:
    $key_9dda = { ca a8 [2] f8 8a [2] fe bf [2] d0 bf [2] ef a3 }

  condition:
    any of them
}