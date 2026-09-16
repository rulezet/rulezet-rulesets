rule TTP_XOR_WriteProcessMemory_7e58 {
  strings:
    $key_7e58 = { 29 2a [2] 1b 08 [2] 1d 3d [2] 33 3d [2] 0c 21 }

  condition:
    any of them
}