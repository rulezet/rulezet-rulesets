rule TTP_XOR_WriteProcessMemory_9d35 {
  strings:
    $key_9d35 = { ca 47 [2] f8 65 [2] fe 50 [2] d0 50 [2] ef 4c }

  condition:
    any of them
}