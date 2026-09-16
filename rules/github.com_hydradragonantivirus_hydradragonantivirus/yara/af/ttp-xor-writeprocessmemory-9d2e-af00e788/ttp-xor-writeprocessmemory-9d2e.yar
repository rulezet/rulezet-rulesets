rule TTP_XOR_WriteProcessMemory_9d2e {
  strings:
    $key_9d2e = { ca 5c [2] f8 7e [2] fe 4b [2] d0 4b [2] ef 57 }

  condition:
    any of them
}