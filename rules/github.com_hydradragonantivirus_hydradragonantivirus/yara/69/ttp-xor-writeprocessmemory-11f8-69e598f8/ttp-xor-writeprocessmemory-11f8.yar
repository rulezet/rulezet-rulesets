rule TTP_XOR_WriteProcessMemory_11f8 {
  strings:
    $key_11f8 = { 46 8a [2] 74 a8 [2] 72 9d [2] 5c 9d [2] 63 81 }

  condition:
    any of them
}