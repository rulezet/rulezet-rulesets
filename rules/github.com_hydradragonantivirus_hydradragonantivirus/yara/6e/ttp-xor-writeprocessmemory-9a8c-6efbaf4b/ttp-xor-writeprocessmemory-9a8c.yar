rule TTP_XOR_WriteProcessMemory_9a8c {
  strings:
    $key_9a8c = { cd fe [2] ff dc [2] f9 e9 [2] d7 e9 [2] e8 f5 }

  condition:
    any of them
}