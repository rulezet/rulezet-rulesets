rule TTP_XOR_WriteProcessMemory_3645 {
  strings:
    $key_3645 = { 61 37 [2] 53 15 [2] 55 20 [2] 7b 20 [2] 44 3c }

  condition:
    any of them
}