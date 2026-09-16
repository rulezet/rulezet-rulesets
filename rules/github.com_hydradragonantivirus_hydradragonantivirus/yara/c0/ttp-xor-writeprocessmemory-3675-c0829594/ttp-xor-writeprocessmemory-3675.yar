rule TTP_XOR_WriteProcessMemory_3675 {
  strings:
    $key_3675 = { 61 07 [2] 53 25 [2] 55 10 [2] 7b 10 [2] 44 0c }

  condition:
    any of them
}