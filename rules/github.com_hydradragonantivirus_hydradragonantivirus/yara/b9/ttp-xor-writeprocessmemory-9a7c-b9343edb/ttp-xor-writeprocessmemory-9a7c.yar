rule TTP_XOR_WriteProcessMemory_9a7c {
  strings:
    $key_9a7c = { cd 0e [2] ff 2c [2] f9 19 [2] d7 19 [2] e8 05 }

  condition:
    any of them
}