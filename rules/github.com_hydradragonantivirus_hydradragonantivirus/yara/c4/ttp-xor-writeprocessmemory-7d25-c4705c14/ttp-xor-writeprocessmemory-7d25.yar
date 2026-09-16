rule TTP_XOR_WriteProcessMemory_7d25 {
  strings:
    $key_7d25 = { 2a 57 [2] 18 75 [2] 1e 40 [2] 30 40 [2] 0f 5c }

  condition:
    any of them
}