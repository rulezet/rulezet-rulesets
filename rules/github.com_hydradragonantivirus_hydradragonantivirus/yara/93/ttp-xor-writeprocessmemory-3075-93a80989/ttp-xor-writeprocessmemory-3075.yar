rule TTP_XOR_WriteProcessMemory_3075 {
  strings:
    $key_3075 = { 67 07 [2] 55 25 [2] 53 10 [2] 7d 10 [2] 42 0c }

  condition:
    any of them
}