rule TTP_XOR_WriteProcessMemory_69f5 {
  strings:
    $key_69f5 = { 3e 87 [2] 0c a5 [2] 0a 90 [2] 24 90 [2] 1b 8c }

  condition:
    any of them
}