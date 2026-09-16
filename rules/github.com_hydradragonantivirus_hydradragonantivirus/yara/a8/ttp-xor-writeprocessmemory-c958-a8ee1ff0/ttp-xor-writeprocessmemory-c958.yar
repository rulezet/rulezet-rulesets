rule TTP_XOR_WriteProcessMemory_c958 {
  strings:
    $key_c958 = { 9e 2a [2] ac 08 [2] aa 3d [2] 84 3d [2] bb 21 }

  condition:
    any of them
}