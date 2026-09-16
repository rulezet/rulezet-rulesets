rule TTP_XOR_WriteProcessMemory_9a0e {
  strings:
    $key_9a0e = { cd 7c [2] ff 5e [2] f9 6b [2] d7 6b [2] e8 77 }

  condition:
    any of them
}