rule TTP_XOR_WriteProcessMemory_2a58 {
  strings:
    $key_2a58 = { 7d 2a [2] 4f 08 [2] 49 3d [2] 67 3d [2] 58 21 }

  condition:
    any of them
}