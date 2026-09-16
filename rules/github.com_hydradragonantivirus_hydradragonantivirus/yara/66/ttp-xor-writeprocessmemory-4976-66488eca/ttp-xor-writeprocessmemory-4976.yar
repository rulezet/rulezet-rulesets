rule TTP_XOR_WriteProcessMemory_4976 {
  strings:
    $key_4976 = { 1e 04 [2] 2c 26 [2] 2a 13 [2] 04 13 [2] 3b 0f }

  condition:
    any of them
}