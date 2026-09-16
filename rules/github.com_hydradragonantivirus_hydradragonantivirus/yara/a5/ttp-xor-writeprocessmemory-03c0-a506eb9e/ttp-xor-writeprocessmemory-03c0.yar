rule TTP_XOR_WriteProcessMemory_03c0 {
  strings:
    $key_03c0 = { 54 b2 [2] 66 90 [2] 60 a5 [2] 4e a5 [2] 71 b9 }

  condition:
    any of them
}