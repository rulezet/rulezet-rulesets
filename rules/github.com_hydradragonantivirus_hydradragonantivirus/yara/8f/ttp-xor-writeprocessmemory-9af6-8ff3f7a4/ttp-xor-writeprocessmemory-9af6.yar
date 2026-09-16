rule TTP_XOR_WriteProcessMemory_9af6 {
  strings:
    $key_9af6 = { cd 84 [2] ff a6 [2] f9 93 [2] d7 93 [2] e8 8f }

  condition:
    any of them
}