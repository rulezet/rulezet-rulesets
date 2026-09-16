rule TTP_XOR_WriteProcessMemory_3e58 {
  strings:
    $key_3e58 = { 69 2a [2] 5b 08 [2] 5d 3d [2] 73 3d [2] 4c 21 }

  condition:
    any of them
}