rule TTP_XOR_WriteProcessMemory_18e1 {
  strings:
    $key_18e1 = { 4f 93 [2] 7d b1 [2] 7b 84 [2] 55 84 [2] 6a 98 }

  condition:
    any of them
}