rule TTP_XOR_WriteProcessMemory_67f8 {
  strings:
    $key_67f8 = { 30 8a [2] 02 a8 [2] 04 9d [2] 2a 9d [2] 15 81 }

  condition:
    any of them
}