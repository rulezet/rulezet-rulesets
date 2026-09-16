rule TTP_XOR_WriteProcessMemory_7d15 {
  strings:
    $key_7d15 = { 2a 67 [2] 18 45 [2] 1e 70 [2] 30 70 [2] 0f 6c }

  condition:
    any of them
}