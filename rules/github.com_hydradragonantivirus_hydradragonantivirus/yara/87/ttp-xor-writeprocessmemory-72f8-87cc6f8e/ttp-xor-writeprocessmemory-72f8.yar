rule TTP_XOR_WriteProcessMemory_72f8 {
  strings:
    $key_72f8 = { 25 8a [2] 17 a8 [2] 11 9d [2] 3f 9d [2] 00 81 }

  condition:
    any of them
}