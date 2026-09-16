rule TTP_XOR_WriteProcessMemory_2e65 {
  strings:
    $key_2e65 = { 79 17 [2] 4b 35 [2] 4d 00 [2] 63 00 [2] 5c 1c }

  condition:
    any of them
}