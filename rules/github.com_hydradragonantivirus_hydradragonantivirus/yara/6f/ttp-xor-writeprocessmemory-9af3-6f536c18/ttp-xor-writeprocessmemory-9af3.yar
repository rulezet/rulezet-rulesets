rule TTP_XOR_WriteProcessMemory_9af3 {
  strings:
    $key_9af3 = { cd 81 [2] ff a3 [2] f9 96 [2] d7 96 [2] e8 8a }

  condition:
    any of them
}