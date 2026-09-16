rule TTP_XOR_WriteProcessMemory_7d45 {
  strings:
    $key_7d45 = { 2a 37 [2] 18 15 [2] 1e 20 [2] 30 20 [2] 0f 3c }

  condition:
    any of them
}