rule TTP_XOR_WriteProcessMemory_1613 {
  strings:
    $key_1613 = { 41 61 [2] 73 43 [2] 75 76 [2] 5b 76 [2] 64 6a }

  condition:
    any of them
}