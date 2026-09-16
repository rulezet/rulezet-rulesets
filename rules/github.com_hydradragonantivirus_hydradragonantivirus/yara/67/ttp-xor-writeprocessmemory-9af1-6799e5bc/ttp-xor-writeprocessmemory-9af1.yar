rule TTP_XOR_WriteProcessMemory_9af1 {
  strings:
    $key_9af1 = { cd 83 [2] ff a1 [2] f9 94 [2] d7 94 [2] e8 88 }

  condition:
    any of them
}