rule TTP_XOR_WriteProcessMemory_6a58 {
  strings:
    $key_6a58 = { 3d 2a [2] 0f 08 [2] 09 3d [2] 27 3d [2] 18 21 }

  condition:
    any of them
}