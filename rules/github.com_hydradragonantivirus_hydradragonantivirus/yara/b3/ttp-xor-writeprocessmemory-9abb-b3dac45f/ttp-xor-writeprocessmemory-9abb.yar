rule TTP_XOR_WriteProcessMemory_9abb {
  strings:
    $key_9abb = { cd c9 [2] ff eb [2] f9 de [2] d7 de [2] e8 c2 }

  condition:
    any of them
}