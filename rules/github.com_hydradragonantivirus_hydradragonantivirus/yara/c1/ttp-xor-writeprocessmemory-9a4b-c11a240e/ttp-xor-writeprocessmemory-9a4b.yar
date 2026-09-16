rule TTP_XOR_WriteProcessMemory_9a4b {
  strings:
    $key_9a4b = { cd 39 [2] ff 1b [2] f9 2e [2] d7 2e [2] e8 32 }

  condition:
    any of them
}