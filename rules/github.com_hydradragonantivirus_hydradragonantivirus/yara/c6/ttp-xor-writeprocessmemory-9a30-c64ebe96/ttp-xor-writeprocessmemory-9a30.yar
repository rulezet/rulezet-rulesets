rule TTP_XOR_WriteProcessMemory_9a30 {
  strings:
    $key_9a30 = { cd 42 [2] ff 60 [2] f9 55 [2] d7 55 [2] e8 49 }

  condition:
    any of them
}