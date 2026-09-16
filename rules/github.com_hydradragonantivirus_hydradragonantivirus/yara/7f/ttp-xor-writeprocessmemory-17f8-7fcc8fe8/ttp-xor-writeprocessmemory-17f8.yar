rule TTP_XOR_WriteProcessMemory_17f8 {
  strings:
    $key_17f8 = { 40 8a [2] 72 a8 [2] 74 9d [2] 5a 9d [2] 65 81 }

  condition:
    any of them
}