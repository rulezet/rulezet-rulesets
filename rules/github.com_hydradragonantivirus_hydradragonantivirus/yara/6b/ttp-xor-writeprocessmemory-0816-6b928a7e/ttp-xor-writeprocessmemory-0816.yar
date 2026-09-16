rule TTP_XOR_WriteProcessMemory_0816 {
  strings:
    $key_0816 = { 5f 64 [2] 6d 46 [2] 6b 73 [2] 45 73 [2] 7a 6f }

  condition:
    any of them
}