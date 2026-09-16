rule TTP_XOR_WriteProcessMemory_9a1c {
  strings:
    $key_9a1c = { cd 6e [2] ff 4c [2] f9 79 [2] d7 79 [2] e8 65 }

  condition:
    any of them
}