rule TTP_XOR_WriteProcessMemory_9dd9 {
  strings:
    $key_9dd9 = { ca ab [2] f8 89 [2] fe bc [2] d0 bc [2] ef a0 }

  condition:
    any of them
}