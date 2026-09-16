rule TTP_XOR_WriteProcessMemory_9dc5 {
  strings:
    $key_9dc5 = { ca b7 [2] f8 95 [2] fe a0 [2] d0 a0 [2] ef bc }

  condition:
    any of them
}