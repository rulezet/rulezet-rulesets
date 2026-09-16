rule TTP_XOR_WriteProcessMemory_9d6a {
  strings:
    $key_9d6a = { ca 18 [2] f8 3a [2] fe 0f [2] d0 0f [2] ef 13 }

  condition:
    any of them
}