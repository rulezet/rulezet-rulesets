rule TTP_XOR_WriteProcessMemory_9bd8 {
  strings:
    $key_9bd8 = { cc aa [2] fe 88 [2] f8 bd [2] d6 bd [2] e9 a1 }

  condition:
    any of them
}