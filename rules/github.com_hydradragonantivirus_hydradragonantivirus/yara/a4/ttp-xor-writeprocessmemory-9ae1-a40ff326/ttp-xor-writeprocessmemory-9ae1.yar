rule TTP_XOR_WriteProcessMemory_9ae1 {
  strings:
    $key_9ae1 = { cd 93 [2] ff b1 [2] f9 84 [2] d7 84 [2] e8 98 }

  condition:
    any of them
}