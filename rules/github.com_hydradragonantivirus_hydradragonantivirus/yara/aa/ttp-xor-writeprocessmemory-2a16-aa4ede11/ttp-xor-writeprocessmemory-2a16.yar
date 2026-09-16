rule TTP_XOR_WriteProcessMemory_2a16 {
  strings:
    $key_2a16 = { 7d 64 [2] 4f 46 [2] 49 73 [2] 67 73 [2] 58 6f }

  condition:
    any of them
}