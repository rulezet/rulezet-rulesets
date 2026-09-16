rule TTP_XOR_WriteProcessMemory_4966 {
  strings:
    $key_4966 = { 1e 14 [2] 2c 36 [2] 2a 03 [2] 04 03 [2] 3b 1f }

  condition:
    any of them
}