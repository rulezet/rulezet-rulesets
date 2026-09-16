rule TTP_XOR_WriteProcessMemory_16f8 {
  strings:
    $key_16f8 = { 41 8a [2] 73 a8 [2] 75 9d [2] 5b 9d [2] 64 81 }

  condition:
    any of them
}