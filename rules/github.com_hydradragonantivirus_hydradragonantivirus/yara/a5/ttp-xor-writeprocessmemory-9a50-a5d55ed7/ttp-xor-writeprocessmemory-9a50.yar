rule TTP_XOR_WriteProcessMemory_9a50 {
  strings:
    $key_9a50 = { cd 22 [2] ff 00 [2] f9 35 [2] d7 35 [2] e8 29 }

  condition:
    any of them
}