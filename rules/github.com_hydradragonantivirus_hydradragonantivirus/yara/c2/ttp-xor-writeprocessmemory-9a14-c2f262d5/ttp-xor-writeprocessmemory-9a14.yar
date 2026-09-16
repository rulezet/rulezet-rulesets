rule TTP_XOR_WriteProcessMemory_9a14 {
  strings:
    $key_9a14 = { cd 66 [2] ff 44 [2] f9 71 [2] d7 71 [2] e8 6d }

  condition:
    any of them
}