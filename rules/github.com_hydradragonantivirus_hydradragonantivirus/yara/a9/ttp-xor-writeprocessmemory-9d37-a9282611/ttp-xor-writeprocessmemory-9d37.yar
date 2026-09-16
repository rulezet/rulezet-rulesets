rule TTP_XOR_WriteProcessMemory_9d37 {
  strings:
    $key_9d37 = { ca 45 [2] f8 67 [2] fe 52 [2] d0 52 [2] ef 4e }

  condition:
    any of them
}