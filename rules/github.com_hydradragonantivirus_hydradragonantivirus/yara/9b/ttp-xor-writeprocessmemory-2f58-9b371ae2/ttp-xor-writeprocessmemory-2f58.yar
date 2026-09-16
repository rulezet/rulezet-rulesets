rule TTP_XOR_WriteProcessMemory_2f58 {
  strings:
    $key_2f58 = { 78 2a [2] 4a 08 [2] 4c 3d [2] 62 3d [2] 5d 21 }

  condition:
    any of them
}