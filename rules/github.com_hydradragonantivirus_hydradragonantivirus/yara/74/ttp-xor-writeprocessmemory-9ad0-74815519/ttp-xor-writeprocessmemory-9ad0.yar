rule TTP_XOR_WriteProcessMemory_9ad0 {
  strings:
    $key_9ad0 = { cd a2 [2] ff 80 [2] f9 b5 [2] d7 b5 [2] e8 a9 }

  condition:
    any of them
}