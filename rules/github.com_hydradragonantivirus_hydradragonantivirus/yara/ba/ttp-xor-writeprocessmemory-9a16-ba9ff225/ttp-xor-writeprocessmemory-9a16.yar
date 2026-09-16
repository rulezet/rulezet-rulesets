rule TTP_XOR_WriteProcessMemory_9a16 {
  strings:
    $key_9a16 = { cd 64 [2] ff 46 [2] f9 73 [2] d7 73 [2] e8 6f }

  condition:
    any of them
}