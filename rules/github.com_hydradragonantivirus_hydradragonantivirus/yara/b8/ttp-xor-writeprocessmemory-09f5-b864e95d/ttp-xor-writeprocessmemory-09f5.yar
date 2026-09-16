rule TTP_XOR_WriteProcessMemory_09f5 {
  strings:
    $key_09f5 = { 5e 87 [2] 6c a5 [2] 6a 90 [2] 44 90 [2] 7b 8c }

  condition:
    any of them
}