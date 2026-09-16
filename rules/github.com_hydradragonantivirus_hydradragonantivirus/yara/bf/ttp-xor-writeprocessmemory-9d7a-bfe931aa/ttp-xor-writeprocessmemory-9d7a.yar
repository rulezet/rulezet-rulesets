rule TTP_XOR_WriteProcessMemory_9d7a {
  strings:
    $key_9d7a = { ca 08 [2] f8 2a [2] fe 1f [2] d0 1f [2] ef 03 }

  condition:
    any of them
}