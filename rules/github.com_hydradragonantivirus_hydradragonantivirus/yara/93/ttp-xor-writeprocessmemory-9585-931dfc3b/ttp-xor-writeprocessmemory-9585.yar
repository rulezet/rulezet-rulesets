rule TTP_XOR_WriteProcessMemory_9585 {
  strings:
    $key_9585 = { c2 f7 [2] f0 d5 [2] f6 e0 [2] d8 e0 [2] e7 fc }

  condition:
    any of them
}