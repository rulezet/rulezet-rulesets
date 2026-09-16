rule TTP_XOR_WriteProcessMemory_12f8 {
  strings:
    $key_12f8 = { 45 8a [2] 77 a8 [2] 71 9d [2] 5f 9d [2] 60 81 }

  condition:
    any of them
}