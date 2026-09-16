rule TTP_XOR_WriteProcessMemory_6a48 {
  strings:
    $key_6a48 = { 3d 3a [2] 0f 18 [2] 09 2d [2] 27 2d [2] 18 31 }

  condition:
    any of them
}