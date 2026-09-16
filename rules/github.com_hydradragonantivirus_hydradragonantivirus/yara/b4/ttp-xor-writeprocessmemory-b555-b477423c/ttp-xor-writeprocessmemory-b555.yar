rule TTP_XOR_WriteProcessMemory_b555 {
  strings:
    $key_b555 = { e2 27 [2] d0 05 [2] d6 30 [2] f8 30 [2] c7 2c }

  condition:
    any of them
}