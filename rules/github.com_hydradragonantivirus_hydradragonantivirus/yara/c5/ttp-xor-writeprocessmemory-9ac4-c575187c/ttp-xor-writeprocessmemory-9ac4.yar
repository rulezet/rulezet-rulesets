rule TTP_XOR_WriteProcessMemory_9ac4 {
  strings:
    $key_9ac4 = { cd b6 [2] ff 94 [2] f9 a1 [2] d7 a1 [2] e8 bd }

  condition:
    any of them
}