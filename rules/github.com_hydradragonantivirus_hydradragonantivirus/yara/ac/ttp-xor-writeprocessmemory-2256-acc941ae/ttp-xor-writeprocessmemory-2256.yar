rule TTP_XOR_WriteProcessMemory_2256 {
  strings:
    $key_2256 = { 75 24 [2] 47 06 [2] 41 33 [2] 6f 33 [2] 50 2f }

  condition:
    any of them
}