rule TTP_XOR_WriteProcessMemory_3674 {
  strings:
    $key_3674 = { 61 06 [2] 53 24 [2] 55 11 [2] 7b 11 [2] 44 0d }

  condition:
    any of them
}