rule TTP_XOR_WriteProcessMemory_9a09 {
  strings:
    $key_9a09 = { cd 7b [2] ff 59 [2] f9 6c [2] d7 6c [2] e8 70 }

  condition:
    any of them
}