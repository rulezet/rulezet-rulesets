rule TTP_XOR_WriteProcessMemory_9bd4 {
  strings:
    $key_9bd4 = { cc a6 [2] fe 84 [2] f8 b1 [2] d6 b1 [2] e9 ad }

  condition:
    any of them
}