rule TTP_XOR_WriteProcessMemory_9a02 {
  strings:
    $key_9a02 = { cd 70 [2] ff 52 [2] f9 67 [2] d7 67 [2] e8 7b }

  condition:
    any of them
}