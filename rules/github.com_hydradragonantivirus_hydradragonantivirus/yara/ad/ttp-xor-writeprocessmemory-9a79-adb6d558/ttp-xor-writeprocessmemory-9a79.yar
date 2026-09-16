rule TTP_XOR_WriteProcessMemory_9a79 {
  strings:
    $key_9a79 = { cd 0b [2] ff 29 [2] f9 1c [2] d7 1c [2] e8 00 }

  condition:
    any of them
}