rule TTP_XOR_WriteProcessMemory_1e02 {
  strings:
    $key_1e02 = { 49 70 [2] 7b 52 [2] 7d 67 [2] 53 67 [2] 6c 7b }

  condition:
    any of them
}