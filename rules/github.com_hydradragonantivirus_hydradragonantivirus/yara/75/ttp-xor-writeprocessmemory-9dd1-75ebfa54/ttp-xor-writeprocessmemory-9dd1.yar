rule TTP_XOR_WriteProcessMemory_9dd1 {
  strings:
    $key_9dd1 = { ca a3 [2] f8 81 [2] fe b4 [2] d0 b4 [2] ef a8 }

  condition:
    any of them
}