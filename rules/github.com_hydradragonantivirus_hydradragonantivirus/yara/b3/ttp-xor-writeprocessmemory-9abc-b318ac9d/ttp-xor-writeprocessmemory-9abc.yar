rule TTP_XOR_WriteProcessMemory_9abc {
  strings:
    $key_9abc = { cd ce [2] ff ec [2] f9 d9 [2] d7 d9 [2] e8 c5 }

  condition:
    any of them
}