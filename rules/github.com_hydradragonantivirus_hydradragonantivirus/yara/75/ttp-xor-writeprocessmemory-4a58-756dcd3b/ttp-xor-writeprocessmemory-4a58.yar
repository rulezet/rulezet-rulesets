rule TTP_XOR_WriteProcessMemory_4a58 {
  strings:
    $key_4a58 = { 1d 2a [2] 2f 08 [2] 29 3d [2] 07 3d [2] 38 21 }

  condition:
    any of them
}