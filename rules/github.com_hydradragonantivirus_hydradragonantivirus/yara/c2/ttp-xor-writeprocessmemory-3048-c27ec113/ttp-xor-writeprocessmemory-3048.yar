rule TTP_XOR_WriteProcessMemory_3048 {
  strings:
    $key_3048 = { 67 3a [2] 55 18 [2] 53 2d [2] 7d 2d [2] 42 31 }

  condition:
    any of them
}