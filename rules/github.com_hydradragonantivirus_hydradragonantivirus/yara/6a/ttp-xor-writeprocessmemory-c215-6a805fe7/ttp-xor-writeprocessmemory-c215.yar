rule TTP_XOR_WriteProcessMemory_c215 {
  strings:
    $key_c215 = { 95 67 [2] a7 45 [2] a1 70 [2] 8f 70 [2] b0 6c }

  condition:
    any of them
}