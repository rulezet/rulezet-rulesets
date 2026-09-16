rule TTP_XOR_WriteProcessMemory_9a9d {
  strings:
    $key_9a9d = { cd ef [2] ff cd [2] f9 f8 [2] d7 f8 [2] e8 e4 }

  condition:
    any of them
}