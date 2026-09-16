rule TTP_XOR_WriteProcessMemory_5d16 {
  strings:
    $key_5d16 = { 0a 64 [2] 38 46 [2] 3e 73 [2] 10 73 [2] 2f 6f }

  condition:
    any of them
}