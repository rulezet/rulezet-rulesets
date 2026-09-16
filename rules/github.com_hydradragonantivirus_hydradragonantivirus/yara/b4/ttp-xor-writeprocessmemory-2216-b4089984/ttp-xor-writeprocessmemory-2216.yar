rule TTP_XOR_WriteProcessMemory_2216 {
  strings:
    $key_2216 = { 75 64 [2] 47 46 [2] 41 73 [2] 6f 73 [2] 50 6f }

  condition:
    any of them
}