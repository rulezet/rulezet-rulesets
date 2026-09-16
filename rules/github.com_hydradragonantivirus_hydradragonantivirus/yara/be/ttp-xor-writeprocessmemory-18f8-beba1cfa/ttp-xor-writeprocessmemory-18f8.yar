rule TTP_XOR_WriteProcessMemory_18f8 {
  strings:
    $key_18f8 = { 4f 8a [2] 7d a8 [2] 7b 9d [2] 55 9d [2] 6a 81 }

  condition:
    any of them
}