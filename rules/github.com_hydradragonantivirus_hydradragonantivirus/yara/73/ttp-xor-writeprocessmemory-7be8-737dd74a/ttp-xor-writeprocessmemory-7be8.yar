rule TTP_XOR_WriteProcessMemory_7be8 {
  strings:
    $key_7be8 = { 2c 9a [2] 1e b8 [2] 18 8d [2] 36 8d [2] 09 91 }

  condition:
    any of them
}