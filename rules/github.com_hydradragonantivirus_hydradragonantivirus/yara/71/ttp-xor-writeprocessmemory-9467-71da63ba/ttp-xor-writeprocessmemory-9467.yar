rule TTP_XOR_WriteProcessMemory_9467 {
  strings:
    $key_9467 = { c3 15 [2] f1 37 [2] f7 02 [2] d9 02 [2] e6 1e }

  condition:
    any of them
}