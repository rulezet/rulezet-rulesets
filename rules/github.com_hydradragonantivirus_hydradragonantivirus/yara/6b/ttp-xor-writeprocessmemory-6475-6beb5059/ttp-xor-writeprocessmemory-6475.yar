rule TTP_XOR_WriteProcessMemory_6475 {
  strings:
    $key_6475 = { 33 07 [2] 01 25 [2] 07 10 [2] 29 10 [2] 16 0c }

  condition:
    any of them
}