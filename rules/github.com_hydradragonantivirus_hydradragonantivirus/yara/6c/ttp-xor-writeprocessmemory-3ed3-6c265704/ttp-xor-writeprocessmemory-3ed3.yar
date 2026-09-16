rule TTP_XOR_WriteProcessMemory_3ed3 {
  strings:
    $key_3ed3 = { 69 a1 [2] 5b 83 [2] 5d b6 [2] 73 b6 [2] 4c aa }

  condition:
    any of them
}