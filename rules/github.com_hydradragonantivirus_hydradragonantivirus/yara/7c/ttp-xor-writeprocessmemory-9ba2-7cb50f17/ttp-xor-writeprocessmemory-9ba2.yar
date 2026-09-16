rule TTP_XOR_WriteProcessMemory_9ba2 {
  strings:
    $key_9ba2 = { cc d0 [2] fe f2 [2] f8 c7 [2] d6 c7 [2] e9 db }

  condition:
    any of them
}