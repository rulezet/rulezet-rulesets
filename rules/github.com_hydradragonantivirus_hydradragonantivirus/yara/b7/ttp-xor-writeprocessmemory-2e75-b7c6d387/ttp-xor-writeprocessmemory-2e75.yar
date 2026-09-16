rule TTP_XOR_WriteProcessMemory_2e75 {
  strings:
    $key_2e75 = { 79 07 [2] 4b 25 [2] 4d 10 [2] 63 10 [2] 5c 0c }

  condition:
    any of them
}