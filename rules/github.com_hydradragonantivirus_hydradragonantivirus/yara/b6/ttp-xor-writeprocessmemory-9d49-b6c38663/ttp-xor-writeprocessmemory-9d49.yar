rule TTP_XOR_WriteProcessMemory_9d49 {
  strings:
    $key_9d49 = { ca 3b [2] f8 19 [2] fe 2c [2] d0 2c [2] ef 30 }

  condition:
    any of them
}