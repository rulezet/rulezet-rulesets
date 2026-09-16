rule TTP_XOR_WriteProcessMemory_41f5 {
  strings:
    $key_41f5 = { 16 87 [2] 24 a5 [2] 22 90 [2] 0c 90 [2] 33 8c }

  condition:
    any of them
}