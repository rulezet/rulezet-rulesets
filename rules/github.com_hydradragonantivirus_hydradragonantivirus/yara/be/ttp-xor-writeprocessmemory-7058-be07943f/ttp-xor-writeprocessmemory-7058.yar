rule TTP_XOR_WriteProcessMemory_7058 {
  strings:
    $key_7058 = { 27 2a [2] 15 08 [2] 13 3d [2] 3d 3d [2] 02 21 }

  condition:
    any of them
}