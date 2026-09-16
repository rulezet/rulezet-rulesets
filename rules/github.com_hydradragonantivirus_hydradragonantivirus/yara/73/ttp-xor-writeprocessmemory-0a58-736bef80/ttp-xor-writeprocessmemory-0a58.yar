rule TTP_XOR_WriteProcessMemory_0a58 {
  strings:
    $key_0a58 = { 5d 2a [2] 6f 08 [2] 69 3d [2] 47 3d [2] 78 21 }

  condition:
    any of them
}