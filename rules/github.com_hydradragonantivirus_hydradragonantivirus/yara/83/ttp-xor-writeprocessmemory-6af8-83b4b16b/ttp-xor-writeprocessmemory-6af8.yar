rule TTP_XOR_WriteProcessMemory_6af8 {
  strings:
    $key_6af8 = { 3d 8a [2] 0f a8 [2] 09 9d [2] 27 9d [2] 18 81 }

  condition:
    any of them
}