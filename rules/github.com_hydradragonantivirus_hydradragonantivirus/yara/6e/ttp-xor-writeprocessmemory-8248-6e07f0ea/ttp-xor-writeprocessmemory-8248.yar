rule TTP_XOR_WriteProcessMemory_8248 {
  strings:
    $key_8248 = { d5 3a [2] e7 18 [2] e1 2d [2] cf 2d [2] f0 31 }

  condition:
    any of them
}