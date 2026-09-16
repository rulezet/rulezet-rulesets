rule TTP_XOR_WriteProcessMemory_9b88 {
  strings:
    $key_9b88 = { cc fa [2] fe d8 [2] f8 ed [2] d6 ed [2] e9 f1 }

  condition:
    any of them
}