rule TTP_XOR_WriteProcessMemory_5bd0 {
  strings:
    $key_5bd0 = { 0c a2 [2] 3e 80 [2] 38 b5 [2] 16 b5 [2] 29 a9 }

  condition:
    any of them
}