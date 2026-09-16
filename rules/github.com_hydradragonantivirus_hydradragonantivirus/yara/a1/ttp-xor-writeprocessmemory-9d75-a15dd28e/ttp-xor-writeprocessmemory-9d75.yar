rule TTP_XOR_WriteProcessMemory_9d75 {
  strings:
    $key_9d75 = { ca 07 [2] f8 25 [2] fe 10 [2] d0 10 [2] ef 0c }

  condition:
    any of them
}