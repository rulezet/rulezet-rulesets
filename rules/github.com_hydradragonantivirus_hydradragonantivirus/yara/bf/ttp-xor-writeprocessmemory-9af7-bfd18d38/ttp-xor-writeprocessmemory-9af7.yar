rule TTP_XOR_WriteProcessMemory_9af7 {
  strings:
    $key_9af7 = { cd 85 [2] ff a7 [2] f9 92 [2] d7 92 [2] e8 8e }

  condition:
    any of them
}