rule TTP_XOR_WriteProcessMemory_9314 {
  strings:
    $key_9314 = { c4 66 [2] f6 44 [2] f0 71 [2] de 71 [2] e1 6d }

  condition:
    any of them
}