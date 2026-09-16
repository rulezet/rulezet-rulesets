rule TTP_XOR_WriteProcessMemory_5848 {
  strings:
    $key_5848 = { 0f 3a [2] 3d 18 [2] 3b 2d [2] 15 2d [2] 2a 31 }

  condition:
    any of them
}