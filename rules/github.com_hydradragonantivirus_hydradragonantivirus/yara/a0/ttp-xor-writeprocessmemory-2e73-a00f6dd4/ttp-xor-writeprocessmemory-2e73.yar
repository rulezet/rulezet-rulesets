rule TTP_XOR_WriteProcessMemory_2e73 {
  strings:
    $key_2e73 = { 79 01 [2] 4b 23 [2] 4d 16 [2] 63 16 [2] 5c 0a }

  condition:
    any of them
}