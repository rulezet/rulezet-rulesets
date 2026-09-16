rule TTP_XOR_WriteProcessMemory_9acc {
  strings:
    $key_9acc = { cd be [2] ff 9c [2] f9 a9 [2] d7 a9 [2] e8 b5 }

  condition:
    any of them
}