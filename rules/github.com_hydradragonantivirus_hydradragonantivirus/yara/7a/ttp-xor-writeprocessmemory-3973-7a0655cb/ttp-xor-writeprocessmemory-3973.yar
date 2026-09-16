rule TTP_XOR_WriteProcessMemory_3973 {
  strings:
    $key_3973 = { 6e 01 [2] 5c 23 [2] 5a 16 [2] 74 16 [2] 4b 0a }

  condition:
    any of them
}