rule TTP_XOR_WriteProcessMemory_6f42 {
  strings:
    $key_6f42 = { 38 30 [2] 0a 12 [2] 0c 27 [2] 22 27 [2] 1d 3b }

  condition:
    any of them
}