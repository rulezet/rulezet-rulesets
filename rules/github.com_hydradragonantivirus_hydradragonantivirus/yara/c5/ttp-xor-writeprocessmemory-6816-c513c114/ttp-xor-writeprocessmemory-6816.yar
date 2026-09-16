rule TTP_XOR_WriteProcessMemory_6816 {
  strings:
    $key_6816 = { 3f 64 [2] 0d 46 [2] 0b 73 [2] 25 73 [2] 1a 6f }

  condition:
    any of them
}