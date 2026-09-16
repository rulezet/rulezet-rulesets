rule TTP_XOR_WriteProcessMemory_5145 {
  strings:
    $key_5145 = { 06 37 [2] 34 15 [2] 32 20 [2] 1c 20 [2] 23 3c }

  condition:
    any of them
}