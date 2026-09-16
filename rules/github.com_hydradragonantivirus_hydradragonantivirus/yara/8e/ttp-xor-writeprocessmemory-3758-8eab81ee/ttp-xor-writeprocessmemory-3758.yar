rule TTP_XOR_WriteProcessMemory_3758 {
  strings:
    $key_3758 = { 60 2a [2] 52 08 [2] 54 3d [2] 7a 3d [2] 45 21 }

  condition:
    any of them
}