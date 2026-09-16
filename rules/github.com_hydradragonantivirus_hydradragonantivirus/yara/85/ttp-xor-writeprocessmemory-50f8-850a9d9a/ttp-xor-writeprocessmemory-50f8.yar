rule TTP_XOR_WriteProcessMemory_50f8 {
  strings:
    $key_50f8 = { 07 8a [2] 35 a8 [2] 33 9d [2] 1d 9d [2] 22 81 }

  condition:
    any of them
}