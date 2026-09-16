rule TTP_XOR_WriteProcessMemory_5475 {
  strings:
    $key_5475 = { 03 07 [2] 31 25 [2] 37 10 [2] 19 10 [2] 26 0c }

  condition:
    any of them
}