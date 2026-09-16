rule TTP_XOR_WriteProcessMemory_9d58 {
  strings:
    $key_9d58 = { ca 2a [2] f8 08 [2] fe 3d [2] d0 3d [2] ef 21 }

  condition:
    any of them
}