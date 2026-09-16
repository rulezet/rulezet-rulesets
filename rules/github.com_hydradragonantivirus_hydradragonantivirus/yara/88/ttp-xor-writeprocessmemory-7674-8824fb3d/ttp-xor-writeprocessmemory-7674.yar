rule TTP_XOR_WriteProcessMemory_7674 {
  strings:
    $key_7674 = { 21 06 [2] 13 24 [2] 15 11 [2] 3b 11 [2] 04 0d }

  condition:
    any of them
}