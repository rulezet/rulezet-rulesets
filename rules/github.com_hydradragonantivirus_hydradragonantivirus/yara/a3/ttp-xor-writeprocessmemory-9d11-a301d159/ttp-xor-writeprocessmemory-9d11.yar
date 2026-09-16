rule TTP_XOR_WriteProcessMemory_9d11 {
  strings:
    $key_9d11 = { ca 63 [2] f8 41 [2] fe 74 [2] d0 74 [2] ef 68 }

  condition:
    any of them
}