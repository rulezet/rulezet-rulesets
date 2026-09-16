rule TTP_XOR_WriteProcessMemory_9d81 {
  strings:
    $key_9d81 = { ca f3 [2] f8 d1 [2] fe e4 [2] d0 e4 [2] ef f8 }

  condition:
    any of them
}