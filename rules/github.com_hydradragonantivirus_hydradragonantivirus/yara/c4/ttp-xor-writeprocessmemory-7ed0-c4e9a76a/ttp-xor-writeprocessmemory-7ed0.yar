rule TTP_XOR_WriteProcessMemory_7ed0 {
  strings:
    $key_7ed0 = { 29 a2 [2] 1b 80 [2] 1d b5 [2] 33 b5 [2] 0c a9 }

  condition:
    any of them
}