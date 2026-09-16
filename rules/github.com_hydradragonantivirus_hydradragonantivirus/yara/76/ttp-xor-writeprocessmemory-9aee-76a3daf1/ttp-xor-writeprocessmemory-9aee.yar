rule TTP_XOR_WriteProcessMemory_9aee {
  strings:
    $key_9aee = { cd 9c [2] ff be [2] f9 8b [2] d7 8b [2] e8 97 }

  condition:
    any of them
}