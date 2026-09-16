rule TTP_XOR_WriteProcessMemory_c916 {
  strings:
    $key_c916 = { 9e 64 [2] ac 46 [2] aa 73 [2] 84 73 [2] bb 6f }

  condition:
    any of them
}