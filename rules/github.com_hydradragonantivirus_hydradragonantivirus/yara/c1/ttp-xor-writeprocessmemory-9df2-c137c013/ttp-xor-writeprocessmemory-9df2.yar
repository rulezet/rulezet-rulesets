rule TTP_XOR_WriteProcessMemory_9df2 {
  strings:
    $key_9df2 = { ca 80 [2] f8 a2 [2] fe 97 [2] d0 97 [2] ef 8b }

  condition:
    any of them
}