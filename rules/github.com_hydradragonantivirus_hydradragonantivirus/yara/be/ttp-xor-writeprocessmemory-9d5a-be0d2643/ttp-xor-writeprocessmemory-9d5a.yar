rule TTP_XOR_WriteProcessMemory_9d5a {
  strings:
    $key_9d5a = { ca 28 [2] f8 0a [2] fe 3f [2] d0 3f [2] ef 23 }

  condition:
    any of them
}