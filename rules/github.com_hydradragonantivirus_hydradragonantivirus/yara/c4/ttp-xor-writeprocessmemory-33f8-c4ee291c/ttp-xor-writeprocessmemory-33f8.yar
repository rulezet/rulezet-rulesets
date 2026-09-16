rule TTP_XOR_WriteProcessMemory_33f8 {
  strings:
    $key_33f8 = { 64 8a [2] 56 a8 [2] 50 9d [2] 7e 9d [2] 41 81 }

  condition:
    any of them
}