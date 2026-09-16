rule TTP_XOR_WriteProcessMemory_9a81 {
  strings:
    $key_9a81 = { cd f3 [2] ff d1 [2] f9 e4 [2] d7 e4 [2] e8 f8 }

  condition:
    any of them
}