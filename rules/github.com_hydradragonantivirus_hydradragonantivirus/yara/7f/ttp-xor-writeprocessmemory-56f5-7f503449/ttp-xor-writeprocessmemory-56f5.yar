rule TTP_XOR_WriteProcessMemory_56f5 {
  strings:
    $key_56f5 = { 01 87 [2] 33 a5 [2] 35 90 [2] 1b 90 [2] 24 8c }

  condition:
    any of them
}