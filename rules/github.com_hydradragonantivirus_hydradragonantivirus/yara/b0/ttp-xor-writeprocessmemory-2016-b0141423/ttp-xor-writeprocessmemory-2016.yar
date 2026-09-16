rule TTP_XOR_WriteProcessMemory_2016 {
  strings:
    $key_2016 = { 77 64 [2] 45 46 [2] 43 73 [2] 6d 73 [2] 52 6f }

  condition:
    any of them
}