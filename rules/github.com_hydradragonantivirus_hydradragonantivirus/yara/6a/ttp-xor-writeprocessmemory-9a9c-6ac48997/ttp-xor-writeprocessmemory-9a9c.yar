rule TTP_XOR_WriteProcessMemory_9a9c {
  strings:
    $key_9a9c = { cd ee [2] ff cc [2] f9 f9 [2] d7 f9 [2] e8 e5 }

  condition:
    any of them
}