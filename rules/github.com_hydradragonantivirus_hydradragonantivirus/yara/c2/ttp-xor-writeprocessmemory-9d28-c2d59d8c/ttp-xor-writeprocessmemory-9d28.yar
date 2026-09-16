rule TTP_XOR_WriteProcessMemory_9d28 {
  strings:
    $key_9d28 = { ca 5a [2] f8 78 [2] fe 4d [2] d0 4d [2] ef 51 }

  condition:
    any of them
}