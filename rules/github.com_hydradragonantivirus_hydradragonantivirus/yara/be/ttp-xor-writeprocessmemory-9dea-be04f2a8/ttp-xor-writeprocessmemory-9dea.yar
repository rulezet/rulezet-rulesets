rule TTP_XOR_WriteProcessMemory_9dea {
  strings:
    $key_9dea = { ca 98 [2] f8 ba [2] fe 8f [2] d0 8f [2] ef 93 }

  condition:
    any of them
}