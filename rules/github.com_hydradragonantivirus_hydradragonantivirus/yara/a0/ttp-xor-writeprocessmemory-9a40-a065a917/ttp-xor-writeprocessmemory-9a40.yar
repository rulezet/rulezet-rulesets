rule TTP_XOR_WriteProcessMemory_9a40 {
  strings:
    $key_9a40 = { cd 32 [2] ff 10 [2] f9 25 [2] d7 25 [2] e8 39 }

  condition:
    any of them
}