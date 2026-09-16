rule TTP_XOR_WriteProcessMemory_61f6 {
  strings:
    $key_61f6 = { 36 84 [2] 04 a6 [2] 02 93 [2] 2c 93 [2] 13 8f }

  condition:
    any of them
}