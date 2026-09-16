rule TTP_XOR_WriteProcessMemory_9bd5 {
  strings:
    $key_9bd5 = { cc a7 [2] fe 85 [2] f8 b0 [2] d6 b0 [2] e9 ac }

  condition:
    any of them
}