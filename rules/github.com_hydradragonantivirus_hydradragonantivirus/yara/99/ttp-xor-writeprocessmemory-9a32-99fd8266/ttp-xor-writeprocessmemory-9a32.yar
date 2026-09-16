rule TTP_XOR_WriteProcessMemory_9a32 {
  strings:
    $key_9a32 = { cd 40 [2] ff 62 [2] f9 57 [2] d7 57 [2] e8 4b }

  condition:
    any of them
}