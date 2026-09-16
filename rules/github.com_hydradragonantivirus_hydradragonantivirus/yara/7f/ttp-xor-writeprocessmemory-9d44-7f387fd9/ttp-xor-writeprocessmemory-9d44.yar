rule TTP_XOR_WriteProcessMemory_9d44 {
  strings:
    $key_9d44 = { ca 36 [2] f8 14 [2] fe 21 [2] d0 21 [2] ef 3d }

  condition:
    any of them
}