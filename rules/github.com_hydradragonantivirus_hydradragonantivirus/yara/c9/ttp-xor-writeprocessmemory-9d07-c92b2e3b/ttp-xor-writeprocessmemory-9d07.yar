rule TTP_XOR_WriteProcessMemory_9d07 {
  strings:
    $key_9d07 = { ca 75 [2] f8 57 [2] fe 62 [2] d0 62 [2] ef 7e }

  condition:
    any of them
}