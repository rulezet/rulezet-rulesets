rule TTP_XOR_WriteProcessMemory_6ff3 {
  strings:
    $key_6ff3 = { 38 81 [2] 0a a3 [2] 0c 96 [2] 22 96 [2] 1d 8a }

  condition:
    any of them
}