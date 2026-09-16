rule TTP_XOR_WriteProcessMemory_9d38 {
  strings:
    $key_9d38 = { ca 4a [2] f8 68 [2] fe 5d [2] d0 5d [2] ef 41 }

  condition:
    any of them
}