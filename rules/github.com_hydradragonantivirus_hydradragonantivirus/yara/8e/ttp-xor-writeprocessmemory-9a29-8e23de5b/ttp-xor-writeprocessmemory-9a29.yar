rule TTP_XOR_WriteProcessMemory_9a29 {
  strings:
    $key_9a29 = { cd 5b [2] ff 79 [2] f9 4c [2] d7 4c [2] e8 50 }

  condition:
    any of them
}