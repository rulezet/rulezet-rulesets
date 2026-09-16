rule TTP_XOR_WriteProcessMemory_9ad3 {
  strings:
    $key_9ad3 = { cd a1 [2] ff 83 [2] f9 b6 [2] d7 b6 [2] e8 aa }

  condition:
    any of them
}