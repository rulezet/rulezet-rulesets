rule TTP_XOR_WriteProcessMemory_7d42 {
  strings:
    $key_7d42 = { 2a 30 [2] 18 12 [2] 1e 27 [2] 30 27 [2] 0f 3b }

  condition:
    any of them
}