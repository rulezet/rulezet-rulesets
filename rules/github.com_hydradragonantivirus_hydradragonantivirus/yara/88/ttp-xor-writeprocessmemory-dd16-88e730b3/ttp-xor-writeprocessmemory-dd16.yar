rule TTP_XOR_WriteProcessMemory_dd16 {
  strings:
    $key_dd16 = { 8a 64 [2] b8 46 [2] be 73 [2] 90 73 [2] af 6f }

  condition:
    any of them
}