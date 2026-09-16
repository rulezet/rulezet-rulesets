rule TTP_XOR_WriteProcessMemory_2e45 {
  strings:
    $key_2e45 = { 79 37 [2] 4b 15 [2] 4d 20 [2] 63 20 [2] 5c 3c }

  condition:
    any of them
}