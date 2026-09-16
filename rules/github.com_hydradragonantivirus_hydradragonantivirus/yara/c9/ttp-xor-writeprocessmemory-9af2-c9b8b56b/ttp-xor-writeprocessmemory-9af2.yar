rule TTP_XOR_WriteProcessMemory_9af2 {
  strings:
    $key_9af2 = { cd 80 [2] ff a2 [2] f9 97 [2] d7 97 [2] e8 8b }

  condition:
    any of them
}