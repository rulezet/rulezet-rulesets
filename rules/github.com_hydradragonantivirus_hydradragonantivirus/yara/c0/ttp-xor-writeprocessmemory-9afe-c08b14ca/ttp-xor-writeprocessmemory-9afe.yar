rule TTP_XOR_WriteProcessMemory_9afe {
  strings:
    $key_9afe = { cd 8c [2] ff ae [2] f9 9b [2] d7 9b [2] e8 87 }

  condition:
    any of them
}