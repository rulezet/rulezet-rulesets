rule TTP_XOR_WriteProcessMemory_7675 {
  strings:
    $key_7675 = { 21 07 [2] 13 25 [2] 15 10 [2] 3b 10 [2] 04 0c }

  condition:
    any of them
}