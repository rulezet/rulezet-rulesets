rule TTP_XOR_WriteProcessMemory_03a6 {
  strings:
    $key_03a6 = { 54 d4 [2] 66 f6 [2] 60 c3 [2] 4e c3 [2] 71 df }

  condition:
    any of them
}