rule TTP_XOR_WriteProcessMemory_e9f5 {
  strings:
    $key_e9f5 = { be 87 [2] 8c a5 [2] 8a 90 [2] a4 90 [2] 9b 8c }

  condition:
    any of them
}