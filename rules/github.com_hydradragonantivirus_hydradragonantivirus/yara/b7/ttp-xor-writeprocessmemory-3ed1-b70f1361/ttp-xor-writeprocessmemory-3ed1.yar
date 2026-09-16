rule TTP_XOR_WriteProcessMemory_3ed1 {
  strings:
    $key_3ed1 = { 69 a3 [2] 5b 81 [2] 5d b4 [2] 73 b4 [2] 4c a8 }

  condition:
    any of them
}