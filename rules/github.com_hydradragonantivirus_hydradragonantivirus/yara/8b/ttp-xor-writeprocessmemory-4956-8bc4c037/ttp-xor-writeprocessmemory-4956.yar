rule TTP_XOR_WriteProcessMemory_4956 {
  strings:
    $key_4956 = { 1e 24 [2] 2c 06 [2] 2a 33 [2] 04 33 [2] 3b 2f }

  condition:
    any of them
}