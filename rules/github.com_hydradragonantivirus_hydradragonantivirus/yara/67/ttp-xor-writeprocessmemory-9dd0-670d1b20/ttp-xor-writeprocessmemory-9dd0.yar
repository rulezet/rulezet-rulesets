rule TTP_XOR_WriteProcessMemory_9dd0 {
  strings:
    $key_9dd0 = { ca a2 [2] f8 80 [2] fe b5 [2] d0 b5 [2] ef a9 }

  condition:
    any of them
}