rule TTP_XOR_WriteProcessMemory_9a7b {
  strings:
    $key_9a7b = { cd 09 [2] ff 2b [2] f9 1e [2] d7 1e [2] e8 02 }

  condition:
    any of them
}