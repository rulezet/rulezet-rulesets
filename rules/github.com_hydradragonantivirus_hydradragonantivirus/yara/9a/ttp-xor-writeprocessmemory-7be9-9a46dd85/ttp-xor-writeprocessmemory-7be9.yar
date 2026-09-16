rule TTP_XOR_WriteProcessMemory_7be9 {
  strings:
    $key_7be9 = { 2c 9b [2] 1e b9 [2] 18 8c [2] 36 8c [2] 09 90 }

  condition:
    any of them
}