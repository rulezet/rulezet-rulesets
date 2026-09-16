rule TTP_XOR_WriteProcessMemory_19f5 {
  strings:
    $key_19f5 = { 4e 87 [2] 7c a5 [2] 7a 90 [2] 54 90 [2] 6b 8c }

  condition:
    any of them
}