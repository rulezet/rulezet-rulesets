rule TTP_XOR_WriteProcessMemory_2ed0 {
  strings:
    $key_2ed0 = { 79 a2 [2] 4b 80 [2] 4d b5 [2] 63 b5 [2] 5c a9 }

  condition:
    any of them
}