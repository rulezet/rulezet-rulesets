rule TTP_XOR_WriteProcessMemory_6c16 {
  strings:
    $key_6c16 = { 3b 64 [2] 09 46 [2] 0f 73 [2] 21 73 [2] 1e 6f }

  condition:
    any of them
}