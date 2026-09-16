rule TTP_XOR_WriteProcessMemory_9bd9 {
  strings:
    $key_9bd9 = { cc ab [2] fe 89 [2] f8 bc [2] d6 bc [2] e9 a0 }

  condition:
    any of them
}