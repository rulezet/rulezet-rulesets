rule TTP_XOR_WriteProcessMemory_6e16 {
  strings:
    $key_6e16 = { 39 64 [2] 0b 46 [2] 0d 73 [2] 23 73 [2] 1c 6f }

  condition:
    any of them
}