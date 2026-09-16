rule TTP_XOR_WriteProcessMemory_1675 {
  strings:
    $key_1675 = { 41 07 [2] 73 25 [2] 75 10 [2] 5b 10 [2] 64 0c }

  condition:
    any of them
}