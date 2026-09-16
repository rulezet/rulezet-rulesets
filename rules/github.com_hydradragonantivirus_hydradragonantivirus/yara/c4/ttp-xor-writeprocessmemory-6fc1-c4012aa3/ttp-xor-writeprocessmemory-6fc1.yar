rule TTP_XOR_WriteProcessMemory_6fc1 {
  strings:
    $key_6fc1 = { 38 b3 [2] 0a 91 [2] 0c a4 [2] 22 a4 [2] 1d b8 }

  condition:
    any of them
}