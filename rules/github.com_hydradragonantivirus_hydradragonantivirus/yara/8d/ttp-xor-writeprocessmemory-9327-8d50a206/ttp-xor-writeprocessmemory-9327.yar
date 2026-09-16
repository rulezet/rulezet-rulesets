rule TTP_XOR_WriteProcessMemory_9327 {
  strings:
    $key_9327 = { c4 55 [2] f6 77 [2] f0 42 [2] de 42 [2] e1 5e }

  condition:
    any of them
}