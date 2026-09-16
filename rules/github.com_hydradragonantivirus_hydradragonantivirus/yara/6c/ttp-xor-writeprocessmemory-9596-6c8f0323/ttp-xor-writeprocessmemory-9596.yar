rule TTP_XOR_WriteProcessMemory_9596 {
  strings:
    $key_9596 = { c2 e4 [2] f0 c6 [2] f6 f3 [2] d8 f3 [2] e7 ef }

  condition:
    any of them
}