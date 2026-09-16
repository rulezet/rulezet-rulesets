rule TTP_XOR_WriteProcessMemory_9a73 {
  strings:
    $key_9a73 = { cd 01 [2] ff 23 [2] f9 16 [2] d7 16 [2] e8 0a }

  condition:
    any of them
}