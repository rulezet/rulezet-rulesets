rule TTP_XOR_WriteProcessMemory_9485 {
  strings:
    $key_9485 = { c3 f7 [2] f1 d5 [2] f7 e0 [2] d9 e0 [2] e6 fc }

  condition:
    any of them
}