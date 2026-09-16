rule TTP_XOR_WriteProcessMemory_5a16 {
  strings:
    $key_5a16 = { 0d 64 [2] 3f 46 [2] 39 73 [2] 17 73 [2] 28 6f }

  condition:
    any of them
}