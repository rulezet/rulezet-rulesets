rule TTP_XOR_WriteProcessMemory_6b16 {
  strings:
    $key_6b16 = { 3c 64 [2] 0e 46 [2] 08 73 [2] 26 73 [2] 19 6f }

  condition:
    any of them
}