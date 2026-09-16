rule TTP_XOR_WriteProcessMemory_0e73 {
  strings:
    $key_0e73 = { 59 01 [2] 6b 23 [2] 6d 16 [2] 43 16 [2] 7c 0a }

  condition:
    any of them
}