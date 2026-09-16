rule TTP_XOR_WriteProcessMemory_5954 {
  strings:
    $key_5954 = { 0e 26 [2] 3c 04 [2] 3a 31 [2] 14 31 [2] 2b 2d }

  condition:
    any of them
}