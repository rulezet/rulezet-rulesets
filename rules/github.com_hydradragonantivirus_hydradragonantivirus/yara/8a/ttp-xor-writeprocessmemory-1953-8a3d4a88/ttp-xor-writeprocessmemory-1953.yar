rule TTP_XOR_WriteProcessMemory_1953 {
  strings:
    $key_1953 = { 4e 21 [2] 7c 03 [2] 7a 36 [2] 54 36 [2] 6b 2a }

  condition:
    any of them
}