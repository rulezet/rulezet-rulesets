rule TTP_XOR_WriteProcessMemory_1058 {
  strings:
    $key_1058 = { 47 2a [2] 75 08 [2] 73 3d [2] 5d 3d [2] 62 21 }

  condition:
    any of them
}