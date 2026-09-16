rule TTP_XOR_WriteProcessMemory_1be0 {
  strings:
    $key_1be0 = { 4c 92 [2] 7e b0 [2] 78 85 [2] 56 85 [2] 69 99 }

  condition:
    any of them
}