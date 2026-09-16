rule TTP_XOR_WriteProcessMemory_59f5 {
  strings:
    $key_59f5 = { 0e 87 [2] 3c a5 [2] 3a 90 [2] 14 90 [2] 2b 8c }

  condition:
    any of them
}