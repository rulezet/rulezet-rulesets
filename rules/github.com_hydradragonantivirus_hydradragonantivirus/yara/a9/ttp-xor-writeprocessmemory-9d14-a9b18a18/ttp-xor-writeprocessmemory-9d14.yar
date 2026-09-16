rule TTP_XOR_WriteProcessMemory_9d14 {
  strings:
    $key_9d14 = { ca 66 [2] f8 44 [2] fe 71 [2] d0 71 [2] ef 6d }

  condition:
    any of them
}