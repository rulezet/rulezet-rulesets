rule TTP_XOR_WriteProcessMemory_2af8 {
  strings:
    $key_2af8 = { 7d 8a [2] 4f a8 [2] 49 9d [2] 67 9d [2] 58 81 }

  condition:
    any of them
}