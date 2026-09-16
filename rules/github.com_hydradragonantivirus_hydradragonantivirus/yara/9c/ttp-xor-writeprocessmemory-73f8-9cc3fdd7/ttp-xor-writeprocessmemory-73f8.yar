rule TTP_XOR_WriteProcessMemory_73f8 {
  strings:
    $key_73f8 = { 24 8a [2] 16 a8 [2] 10 9d [2] 3e 9d [2] 01 81 }

  condition:
    any of them
}