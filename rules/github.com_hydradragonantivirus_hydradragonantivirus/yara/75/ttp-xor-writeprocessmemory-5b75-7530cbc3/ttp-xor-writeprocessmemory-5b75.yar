rule TTP_XOR_WriteProcessMemory_5b75 {
  strings:
    $key_5b75 = { 0c 07 [2] 3e 25 [2] 38 10 [2] 16 10 [2] 29 0c }

  condition:
    any of them
}