rule TTP_XOR_WriteProcessMemory_9dd8 {
  strings:
    $key_9dd8 = { ca aa [2] f8 88 [2] fe bd [2] d0 bd [2] ef a1 }

  condition:
    any of them
}