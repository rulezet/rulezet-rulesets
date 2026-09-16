rule TTP_XOR_WriteProcessMemory_9d2c {
  strings:
    $key_9d2c = { ca 5e [2] f8 7c [2] fe 49 [2] d0 49 [2] ef 55 }

  condition:
    any of them
}