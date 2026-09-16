rule TTP_XOR_WriteProcessMemory_2b16 {
  strings:
    $key_2b16 = { 7c 64 [2] 4e 46 [2] 48 73 [2] 66 73 [2] 59 6f }

  condition:
    any of them
}