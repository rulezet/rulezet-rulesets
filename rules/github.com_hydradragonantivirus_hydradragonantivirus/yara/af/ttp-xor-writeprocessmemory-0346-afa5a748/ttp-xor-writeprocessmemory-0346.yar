rule TTP_XOR_WriteProcessMemory_0346 {
  strings:
    $key_0346 = { 54 34 [2] 66 16 [2] 60 23 [2] 4e 23 [2] 71 3f }

  condition:
    any of them
}