rule TTP_XOR_WriteProcessMemory_30d0 {
  strings:
    $key_30d0 = { 67 a2 [2] 55 80 [2] 53 b5 [2] 7d b5 [2] 42 a9 }

  condition:
    any of them
}