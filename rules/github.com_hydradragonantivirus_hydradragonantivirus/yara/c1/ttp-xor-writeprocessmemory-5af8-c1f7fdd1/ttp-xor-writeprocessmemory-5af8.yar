rule TTP_XOR_WriteProcessMemory_5af8 {
  strings:
    $key_5af8 = { 0d 8a [2] 3f a8 [2] 39 9d [2] 17 9d [2] 28 81 }

  condition:
    any of them
}