rule TTP_XOR_WriteProcessMemory_6f58 {
  strings:
    $key_6f58 = { 38 2a [2] 0a 08 [2] 0c 3d [2] 22 3d [2] 1d 21 }

  condition:
    any of them
}