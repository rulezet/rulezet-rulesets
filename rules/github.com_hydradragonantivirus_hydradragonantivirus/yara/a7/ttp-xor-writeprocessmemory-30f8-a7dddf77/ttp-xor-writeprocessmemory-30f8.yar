rule TTP_XOR_WriteProcessMemory_30f8 {
  strings:
    $key_30f8 = { 67 8a [2] 55 a8 [2] 53 9d [2] 7d 9d [2] 42 81 }

  condition:
    any of them
}