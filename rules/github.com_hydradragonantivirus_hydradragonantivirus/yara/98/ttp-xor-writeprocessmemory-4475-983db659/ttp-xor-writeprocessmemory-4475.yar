rule TTP_XOR_WriteProcessMemory_4475 {
  strings:
    $key_4475 = { 13 07 [2] 21 25 [2] 27 10 [2] 09 10 [2] 36 0c }

  condition:
    any of them
}