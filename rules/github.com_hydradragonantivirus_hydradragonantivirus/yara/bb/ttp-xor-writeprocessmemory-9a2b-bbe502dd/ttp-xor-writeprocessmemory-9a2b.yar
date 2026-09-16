rule TTP_XOR_WriteProcessMemory_9a2b {
  strings:
    $key_9a2b = { cd 59 [2] ff 7b [2] f9 4e [2] d7 4e [2] e8 52 }

  condition:
    any of them
}