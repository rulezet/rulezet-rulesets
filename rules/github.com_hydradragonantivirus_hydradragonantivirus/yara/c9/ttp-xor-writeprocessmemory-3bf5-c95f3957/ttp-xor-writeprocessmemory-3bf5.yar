rule TTP_XOR_WriteProcessMemory_3bf5 {
  strings:
    $key_3bf5 = { 6c 87 [2] 5e a5 [2] 58 90 [2] 76 90 [2] 49 8c }

  condition:
    any of them
}