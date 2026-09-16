rule TTP_XOR_WriteProcessMemory_9de8 {
  strings:
    $key_9de8 = { ca 9a [2] f8 b8 [2] fe 8d [2] d0 8d [2] ef 91 }

  condition:
    any of them
}