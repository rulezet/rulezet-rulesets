rule TTP_XOR_WriteProcessMemory_7673 {
  strings:
    $key_7673 = { 21 01 [2] 13 23 [2] 15 16 [2] 3b 16 [2] 04 0a }

  condition:
    any of them
}