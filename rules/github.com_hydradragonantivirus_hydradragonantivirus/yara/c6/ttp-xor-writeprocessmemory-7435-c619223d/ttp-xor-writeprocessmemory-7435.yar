rule TTP_XOR_WriteProcessMemory_7435 {
  strings:
    $key_7435 = { 23 47 [2] 11 65 [2] 17 50 [2] 39 50 [2] 06 4c }

  condition:
    any of them
}