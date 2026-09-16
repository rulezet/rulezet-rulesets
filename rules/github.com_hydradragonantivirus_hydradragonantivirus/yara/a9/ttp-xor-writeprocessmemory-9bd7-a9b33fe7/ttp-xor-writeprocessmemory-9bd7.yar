rule TTP_XOR_WriteProcessMemory_9bd7 {
  strings:
    $key_9bd7 = { cc a5 [2] fe 87 [2] f8 b2 [2] d6 b2 [2] e9 ae }

  condition:
    any of them
}