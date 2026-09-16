rule TTP_XOR_WriteProcessMemory_2ed1 {
  strings:
    $key_2ed1 = { 79 a3 [2] 4b 81 [2] 4d b4 [2] 63 b4 [2] 5c a8 }

  condition:
    any of them
}