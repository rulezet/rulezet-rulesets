rule TTP_XOR_WriteProcessMemory_5058 {
  strings:
    $key_5058 = { 07 2a [2] 35 08 [2] 33 3d [2] 1d 3d [2] 22 21 }

  condition:
    any of them
}