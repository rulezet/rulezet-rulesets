rule TTP_XOR_WriteProcessMemory_9a8a {
  strings:
    $key_9a8a = { cd f8 [2] ff da [2] f9 ef [2] d7 ef [2] e8 f3 }

  condition:
    any of them
}