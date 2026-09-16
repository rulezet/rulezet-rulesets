rule TTP_XOR_WriteProcessMemory_03f0 {
  strings:
    $key_03f0 = { 54 82 [2] 66 a0 [2] 60 95 [2] 4e 95 [2] 71 89 }

  condition:
    any of them
}