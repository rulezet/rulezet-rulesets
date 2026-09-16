rule TTP_XOR_WriteProcessMemory_0016 {
  strings:
    $key_0016 = { 57 64 [2] 65 46 [2] 63 73 [2] 4d 73 [2] 72 6f }

  condition:
    any of them
}