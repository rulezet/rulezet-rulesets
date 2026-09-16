rule TTP_XOR_WriteProcessMemory_2145 {
  strings:
    $key_2145 = { 76 37 [2] 44 15 [2] 42 20 [2] 6c 20 [2] 53 3c }

  condition:
    any of them
}