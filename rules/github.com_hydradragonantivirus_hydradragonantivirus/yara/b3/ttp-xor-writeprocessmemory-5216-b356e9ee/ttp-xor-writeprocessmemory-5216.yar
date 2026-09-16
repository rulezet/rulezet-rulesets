rule TTP_XOR_WriteProcessMemory_5216 {
  strings:
    $key_5216 = { 05 64 [2] 37 46 [2] 31 73 [2] 1f 73 [2] 20 6f }

  condition:
    any of them
}