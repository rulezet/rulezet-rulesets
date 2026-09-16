rule TTP_XOR_WriteProcessMemory_9d86 {
  strings:
    $key_9d86 = { ca f4 [2] f8 d6 [2] fe e3 [2] d0 e3 [2] ef ff }

  condition:
    any of them
}