rule TTP_XOR_WriteProcessMemory_65f8 {
  strings:
    $key_65f8 = { 32 8a [2] 00 a8 [2] 06 9d [2] 28 9d [2] 17 81 }

  condition:
    any of them
}