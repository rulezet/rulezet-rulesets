rule TTP_XOR_WriteProcessMemory_0342 {
  strings:
    $key_0342 = { 54 30 [2] 66 12 [2] 60 27 [2] 4e 27 [2] 71 3b }

  condition:
    any of them
}