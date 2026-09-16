rule TTP_XOR_WriteProcessMemory_7b06 {
  strings:
    $key_7b06 = { 2c 74 [2] 1e 56 [2] 18 63 [2] 36 63 [2] 09 7f }

  condition:
    any of them
}