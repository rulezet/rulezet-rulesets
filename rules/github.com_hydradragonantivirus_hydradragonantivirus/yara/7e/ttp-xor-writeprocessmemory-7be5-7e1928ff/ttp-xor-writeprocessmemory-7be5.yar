rule TTP_XOR_WriteProcessMemory_7be5 {
  strings:
    $key_7be5 = { 2c 97 [2] 1e b5 [2] 18 80 [2] 36 80 [2] 09 9c }

  condition:
    any of them
}