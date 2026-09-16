rule TTP_XOR_WriteProcessMemory_2e55 {
  strings:
    $key_2e55 = { 79 27 [2] 4b 05 [2] 4d 30 [2] 63 30 [2] 5c 2c }

  condition:
    any of them
}