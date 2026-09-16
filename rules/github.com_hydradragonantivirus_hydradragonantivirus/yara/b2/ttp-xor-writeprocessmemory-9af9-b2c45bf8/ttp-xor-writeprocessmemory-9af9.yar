rule TTP_XOR_WriteProcessMemory_9af9 {
  strings:
    $key_9af9 = { cd 8b [2] ff a9 [2] f9 9c [2] d7 9c [2] e8 80 }

  condition:
    any of them
}