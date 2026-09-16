rule TTP_XOR_WriteProcessMemory_9bce {
  strings:
    $key_9bce = { cc bc [2] fe 9e [2] f8 ab [2] d6 ab [2] e9 b7 }

  condition:
    any of them
}