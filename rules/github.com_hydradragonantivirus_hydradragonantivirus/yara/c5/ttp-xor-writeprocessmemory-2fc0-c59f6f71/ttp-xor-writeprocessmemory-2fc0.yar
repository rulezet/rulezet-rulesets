rule TTP_XOR_WriteProcessMemory_2fc0 {
  strings:
    $key_2fc0 = { 78 b2 [2] 4a 90 [2] 4c a5 [2] 62 a5 [2] 5d b9 }

  condition:
    any of them
}