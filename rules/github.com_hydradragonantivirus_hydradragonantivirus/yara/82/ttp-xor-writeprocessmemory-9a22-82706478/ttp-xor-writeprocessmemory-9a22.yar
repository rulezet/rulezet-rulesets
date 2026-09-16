rule TTP_XOR_WriteProcessMemory_9a22 {
  strings:
    $key_9a22 = { cd 50 [2] ff 72 [2] f9 47 [2] d7 47 [2] e8 5b }

  condition:
    any of them
}