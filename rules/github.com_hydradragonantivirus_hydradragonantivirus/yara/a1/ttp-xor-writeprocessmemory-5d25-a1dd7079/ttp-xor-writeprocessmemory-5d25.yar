rule TTP_XOR_WriteProcessMemory_5d25 {
  strings:
    $key_5d25 = { 0a 57 [2] 38 75 [2] 3e 40 [2] 10 40 [2] 2f 5c }

  condition:
    any of them
}