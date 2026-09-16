rule TTP_XOR_WriteProcessMemory_9d87 {
  strings:
    $key_9d87 = { ca f5 [2] f8 d7 [2] fe e2 [2] d0 e2 [2] ef fe }

  condition:
    any of them
}