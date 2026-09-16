rule TTP_XOR_WriteProcessMemory_18e4 {
  strings:
    $key_18e4 = { 4f 96 [2] 7d b4 [2] 7b 81 [2] 55 81 [2] 6a 9d }

  condition:
    any of them
}