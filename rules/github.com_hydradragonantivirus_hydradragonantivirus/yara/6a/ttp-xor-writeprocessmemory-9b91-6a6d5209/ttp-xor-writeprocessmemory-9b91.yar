rule TTP_XOR_WriteProcessMemory_9b91 {
  strings:
    $key_9b91 = { cc e3 [2] fe c1 [2] f8 f4 [2] d6 f4 [2] e9 e8 }

  condition:
    any of them
}