rule TTP_XOR_WriteProcessMemory_9beb {
  strings:
    $key_9beb = { cc 99 [2] fe bb [2] f8 8e [2] d6 8e [2] e9 92 }

  condition:
    any of them
}