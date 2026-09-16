rule TTP_XOR_WriteProcessMemory_9ad4 {
  strings:
    $key_9ad4 = { cd a6 [2] ff 84 [2] f9 b1 [2] d7 b1 [2] e8 ad }

  condition:
    any of them
}