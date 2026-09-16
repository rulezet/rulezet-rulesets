rule TTP_XOR_WriteProcessMemory_9d94 {
  strings:
    $key_9d94 = { ca e6 [2] f8 c4 [2] fe f1 [2] d0 f1 [2] ef ed }

  condition:
    any of them
}