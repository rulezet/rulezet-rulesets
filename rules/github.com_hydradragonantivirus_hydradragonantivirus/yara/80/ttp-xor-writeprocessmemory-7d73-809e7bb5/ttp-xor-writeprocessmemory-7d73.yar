rule TTP_XOR_WriteProcessMemory_7d73 {
  strings:
    $key_7d73 = { 2a 01 [2] 18 23 [2] 1e 16 [2] 30 16 [2] 0f 0a }

  condition:
    any of them
}