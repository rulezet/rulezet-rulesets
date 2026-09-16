rule TTP_XOR_WriteProcessMemory_3116 {
  strings:
    $key_3116 = { 66 64 [2] 54 46 [2] 52 73 [2] 7c 73 [2] 43 6f }

  condition:
    any of them
}