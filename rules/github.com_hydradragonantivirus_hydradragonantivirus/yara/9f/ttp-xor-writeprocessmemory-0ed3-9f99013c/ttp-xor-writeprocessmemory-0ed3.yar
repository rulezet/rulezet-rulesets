rule TTP_XOR_WriteProcessMemory_0ed3 {
  strings:
    $key_0ed3 = { 59 a1 [2] 6b 83 [2] 6d b6 [2] 43 b6 [2] 7c aa }

  condition:
    any of them
}