rule TTP_XOR_WriteProcessMemory_6613 {
  strings:
    $key_6613 = { 31 61 [2] 03 43 [2] 05 76 [2] 2b 76 [2] 14 6a }

  condition:
    any of them
}