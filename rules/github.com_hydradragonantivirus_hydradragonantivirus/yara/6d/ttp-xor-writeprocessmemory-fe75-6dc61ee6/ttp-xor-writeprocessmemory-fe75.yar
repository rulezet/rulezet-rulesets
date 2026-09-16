rule TTP_XOR_WriteProcessMemory_fe75 {
  strings:
    $key_fe75 = { a9 07 [2] 9b 25 [2] 9d 10 [2] b3 10 [2] 8c 0c }

  condition:
    any of them
}