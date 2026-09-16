rule TTP_XOR_WriteProcessMemory_9ab2 {
  strings:
    $key_9ab2 = { cd c0 [2] ff e2 [2] f9 d7 [2] d7 d7 [2] e8 cb }

  condition:
    any of them
}