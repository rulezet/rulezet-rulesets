rule TTP_XOR_WriteProcessMemory_9d34 {
  strings:
    $key_9d34 = { ca 46 [2] f8 64 [2] fe 51 [2] d0 51 [2] ef 4d }

  condition:
    any of them
}