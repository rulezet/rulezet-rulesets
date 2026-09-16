rule TTP_XOR_WriteProcessMemory_9421 {
  strings:
    $key_9421 = { c3 53 [2] f1 71 [2] f7 44 [2] d9 44 [2] e6 58 }

  condition:
    any of them
}