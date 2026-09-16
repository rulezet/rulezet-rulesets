rule TTP_XOR_WriteProcessMemory_1915 {
  strings:
    $key_1915 = { 4e 67 [2] 7c 45 [2] 7a 70 [2] 54 70 [2] 6b 6c }

  condition:
    any of them
}