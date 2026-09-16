rule TTP_XOR_WriteProcessMemory_7be2 {
  strings:
    $key_7be2 = { 2c 90 [2] 1e b2 [2] 18 87 [2] 36 87 [2] 09 9b }

  condition:
    any of them
}