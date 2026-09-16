rule TTP_XOR_WriteProcessMemory_9dfc {
  strings:
    $key_9dfc = { ca 8e [2] f8 ac [2] fe 99 [2] d0 99 [2] ef 85 }

  condition:
    any of them
}