rule TTP_XOR_WriteProcessMemory_4906 {
  strings:
    $key_4906 = { 1e 74 [2] 2c 56 [2] 2a 63 [2] 04 63 [2] 3b 7f }

  condition:
    any of them
}