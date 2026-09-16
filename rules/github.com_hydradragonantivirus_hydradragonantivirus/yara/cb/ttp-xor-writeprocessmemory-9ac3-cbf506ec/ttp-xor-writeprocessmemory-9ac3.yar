rule TTP_XOR_WriteProcessMemory_9ac3 {
  strings:
    $key_9ac3 = { cd b1 [2] ff 93 [2] f9 a6 [2] d7 a6 [2] e8 ba }

  condition:
    any of them
}