rule TTP_XOR_WriteProcessMemory_5be0 {
  strings:
    $key_5be0 = { 0c 92 [2] 3e b0 [2] 38 85 [2] 16 85 [2] 29 99 }

  condition:
    any of them
}