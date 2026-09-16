rule TTP_XOR_WriteProcessMemory_9d4c {
  strings:
    $key_9d4c = { ca 3e [2] f8 1c [2] fe 29 [2] d0 29 [2] ef 35 }

  condition:
    any of them
}