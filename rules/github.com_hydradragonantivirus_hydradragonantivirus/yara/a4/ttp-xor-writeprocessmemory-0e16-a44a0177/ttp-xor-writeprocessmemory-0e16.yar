rule TTP_XOR_WriteProcessMemory_0e16 {
  strings:
    $key_0e16 = { 59 64 [2] 6b 46 [2] 6d 73 [2] 43 73 [2] 7c 6f }

  condition:
    any of them
}