rule TTP_XOR_WriteProcessMemory_2e25 {
  strings:
    $key_2e25 = { 79 57 [2] 4b 75 [2] 4d 40 [2] 63 40 [2] 5c 5c }

  condition:
    any of them
}