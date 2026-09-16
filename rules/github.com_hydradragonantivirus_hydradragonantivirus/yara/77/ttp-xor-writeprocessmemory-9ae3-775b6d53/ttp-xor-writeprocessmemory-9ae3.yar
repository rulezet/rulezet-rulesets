rule TTP_XOR_WriteProcessMemory_9ae3 {
  strings:
    $key_9ae3 = { cd 91 [2] ff b3 [2] f9 86 [2] d7 86 [2] e8 9a }

  condition:
    any of them
}