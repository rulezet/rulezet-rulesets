rule TTP_XOR_WriteProcessMemory_9ad1 {
  strings:
    $key_9ad1 = { cd a3 [2] ff 81 [2] f9 b4 [2] d7 b4 [2] e8 a8 }

  condition:
    any of them
}