rule TTP_XOR_WriteProcessMemory_9dc3 {
  strings:
    $key_9dc3 = { ca b1 [2] f8 93 [2] fe a6 [2] d0 a6 [2] ef ba }

  condition:
    any of them
}