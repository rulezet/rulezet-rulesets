rule TTP_XOR_WriteProcessMemory_9ad6 {
  strings:
    $key_9ad6 = { cd a4 [2] ff 86 [2] f9 b3 [2] d7 b3 [2] e8 af }

  condition:
    any of them
}