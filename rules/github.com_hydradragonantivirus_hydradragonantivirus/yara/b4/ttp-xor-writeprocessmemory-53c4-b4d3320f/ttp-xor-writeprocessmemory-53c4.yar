rule TTP_XOR_WriteProcessMemory_53c4 {
  strings:
    $key_53c4 = { 04 b6 [2] 36 94 [2] 30 a1 [2] 1e a1 [2] 21 bd }

  condition:
    any of them
}