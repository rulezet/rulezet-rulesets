rule TTP_XOR_WriteProcessMemory_6126 {
  strings:
    $key_6126 = { 36 54 [2] 04 76 [2] 02 43 [2] 2c 43 [2] 13 5f }

  condition:
    any of them
}