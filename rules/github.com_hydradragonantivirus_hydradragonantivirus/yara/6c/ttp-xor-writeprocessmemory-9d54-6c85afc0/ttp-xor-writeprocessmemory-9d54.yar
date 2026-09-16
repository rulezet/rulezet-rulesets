rule TTP_XOR_WriteProcessMemory_9d54 {
  strings:
    $key_9d54 = { ca 26 [2] f8 04 [2] fe 31 [2] d0 31 [2] ef 2d }

  condition:
    any of them
}