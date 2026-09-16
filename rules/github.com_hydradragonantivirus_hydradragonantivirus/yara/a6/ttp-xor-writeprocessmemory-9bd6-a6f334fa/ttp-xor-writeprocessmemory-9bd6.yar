rule TTP_XOR_WriteProcessMemory_9bd6 {
  strings:
    $key_9bd6 = { cc a4 [2] fe 86 [2] f8 b3 [2] d6 b3 [2] e9 af }

  condition:
    any of them
}