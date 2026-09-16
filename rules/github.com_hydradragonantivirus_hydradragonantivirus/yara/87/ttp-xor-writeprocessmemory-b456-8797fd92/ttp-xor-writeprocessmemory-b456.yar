rule TTP_XOR_WriteProcessMemory_b456 {
  strings:
    $key_b456 = { e3 24 [2] d1 06 [2] d7 33 [2] f9 33 [2] c6 2f }

  condition:
    any of them
}