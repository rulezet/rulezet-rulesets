rule TTP_XOR_WriteProcessMemory_9b04 {
  strings:
    $key_9b04 = { cc 76 [2] fe 54 [2] f8 61 [2] d6 61 [2] e9 7d }

  condition:
    any of them
}