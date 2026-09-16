rule TTP_XOR_WriteProcessMemory_8258 {
  strings:
    $key_8258 = { d5 2a [2] e7 08 [2] e1 3d [2] cf 3d [2] f0 21 }

  condition:
    any of them
}