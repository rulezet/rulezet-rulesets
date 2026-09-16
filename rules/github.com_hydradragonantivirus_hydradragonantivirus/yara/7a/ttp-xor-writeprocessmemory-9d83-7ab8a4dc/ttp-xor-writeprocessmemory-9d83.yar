rule TTP_XOR_WriteProcessMemory_9d83 {
  strings:
    $key_9d83 = { ca f1 [2] f8 d3 [2] fe e6 [2] d0 e6 [2] ef fa }

  condition:
    any of them
}