rule TTP_XOR_WriteProcessMemory_9d77 {
  strings:
    $key_9d77 = { ca 05 [2] f8 27 [2] fe 12 [2] d0 12 [2] ef 0e }

  condition:
    any of them
}