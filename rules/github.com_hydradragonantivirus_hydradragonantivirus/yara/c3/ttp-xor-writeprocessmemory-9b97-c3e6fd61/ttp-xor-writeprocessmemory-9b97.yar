rule TTP_XOR_WriteProcessMemory_9b97 {
  strings:
    $key_9b97 = { cc e5 [2] fe c7 [2] f8 f2 [2] d6 f2 [2] e9 ee }

  condition:
    any of them
}