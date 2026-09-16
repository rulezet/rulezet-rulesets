rule TTP_XOR_WriteProcessMemory_9a68 {
  strings:
    $key_9a68 = { cd 1a [2] ff 38 [2] f9 0d [2] d7 0d [2] e8 11 }

  condition:
    any of them
}