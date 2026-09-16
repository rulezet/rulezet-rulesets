rule TTP_XOR_WriteProcessMemory_03a3 {
  strings:
    $key_03a3 = { 54 d1 [2] 66 f3 [2] 60 c6 [2] 4e c6 [2] 71 da }

  condition:
    any of them
}