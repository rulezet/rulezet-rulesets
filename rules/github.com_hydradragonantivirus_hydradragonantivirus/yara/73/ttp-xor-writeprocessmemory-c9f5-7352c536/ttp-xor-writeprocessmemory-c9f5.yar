rule TTP_XOR_WriteProcessMemory_c9f5 {
  strings:
    $key_c9f5 = { 9e 87 [2] ac a5 [2] aa 90 [2] 84 90 [2] bb 8c }

  condition:
    any of them
}