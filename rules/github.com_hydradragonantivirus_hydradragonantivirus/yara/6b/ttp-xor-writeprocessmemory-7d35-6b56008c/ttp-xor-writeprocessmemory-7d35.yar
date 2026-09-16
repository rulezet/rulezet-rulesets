rule TTP_XOR_WriteProcessMemory_7d35 {
  strings:
    $key_7d35 = { 2a 47 [2] 18 65 [2] 1e 50 [2] 30 50 [2] 0f 4c }

  condition:
    any of them
}