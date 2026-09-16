rule TTP_XOR_WriteProcessMemory_53f5 {
  strings:
    $key_53f5 = { 04 87 [2] 36 a5 [2] 30 90 [2] 1e 90 [2] 21 8c }

  condition:
    any of them
}