rule TTP_XOR_WriteProcessMemory_9456 {
  strings:
    $key_9456 = { c3 24 [2] f1 06 [2] f7 33 [2] d9 33 [2] e6 2f }

  condition:
    any of them
}