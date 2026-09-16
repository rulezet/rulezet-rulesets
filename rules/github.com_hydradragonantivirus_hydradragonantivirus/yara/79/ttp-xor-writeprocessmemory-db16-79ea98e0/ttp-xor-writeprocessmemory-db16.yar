rule TTP_XOR_WriteProcessMemory_db16 {
  strings:
    $key_db16 = { 8c 64 [2] be 46 [2] b8 73 [2] 96 73 [2] a9 6f }

  condition:
    any of them
}