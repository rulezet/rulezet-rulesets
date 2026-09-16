rule TTP_XOR_WriteProcessMemory_6916 {
  strings:
    $key_6916 = { 3e 64 [2] 0c 46 [2] 0a 73 [2] 24 73 [2] 1b 6f }

  condition:
    any of them
}