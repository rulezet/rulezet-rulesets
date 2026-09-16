rule TTP_XOR_WriteProcessMemory_53d2 {
  strings:
    $key_53d2 = { 04 a0 [2] 36 82 [2] 30 b7 [2] 1e b7 [2] 21 ab }

  condition:
    any of them
}