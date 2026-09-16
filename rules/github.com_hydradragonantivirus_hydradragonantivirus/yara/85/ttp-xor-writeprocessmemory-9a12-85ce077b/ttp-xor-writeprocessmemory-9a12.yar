rule TTP_XOR_WriteProcessMemory_9a12 {
  strings:
    $key_9a12 = { cd 60 [2] ff 42 [2] f9 77 [2] d7 77 [2] e8 6b }

  condition:
    any of them
}