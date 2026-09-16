rule TTP_XOR_WriteProcessMemory_47f8 {
  strings:
    $key_47f8 = { 10 8a [2] 22 a8 [2] 24 9d [2] 0a 9d [2] 35 81 }

  condition:
    any of them
}