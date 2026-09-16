rule TTP_XOR_WriteProcessMemory_7be0 {
  strings:
    $key_7be0 = { 2c 92 [2] 1e b0 [2] 18 85 [2] 36 85 [2] 09 99 }

  condition:
    any of them
}