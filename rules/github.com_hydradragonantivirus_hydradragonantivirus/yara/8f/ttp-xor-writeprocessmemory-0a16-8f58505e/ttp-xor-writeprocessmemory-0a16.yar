rule TTP_XOR_WriteProcessMemory_0a16 {
  strings:
    $key_0a16 = { 5d 64 [2] 6f 46 [2] 69 73 [2] 47 73 [2] 78 6f }

  condition:
    any of them
}