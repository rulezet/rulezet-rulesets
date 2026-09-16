rule TTP_XOR_WriteProcessMemory_8268 {
  strings:
    $key_8268 = { d5 1a [2] e7 38 [2] e1 0d [2] cf 0d [2] f0 11 }

  condition:
    any of them
}