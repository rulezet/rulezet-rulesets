rule TTP_XOR_WriteProcessMemory_9416 {
  strings:
    $key_9416 = { c3 64 [2] f1 46 [2] f7 73 [2] d9 73 [2] e6 6f }

  condition:
    any of them
}