rule TTP_XOR_WriteProcessMemory_9a4e {
  strings:
    $key_9a4e = { cd 3c [2] ff 1e [2] f9 2b [2] d7 2b [2] e8 37 }

  condition:
    any of them
}