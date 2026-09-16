rule TTP_XOR_WriteProcessMemory_7af8 {
  strings:
    $key_7af8 = { 2d 8a [2] 1f a8 [2] 19 9d [2] 37 9d [2] 08 81 }

  condition:
    any of them
}