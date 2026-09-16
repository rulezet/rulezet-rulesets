rule TTP_XOR_WriteProcessMemory_03d9 {
  strings:
    $key_03d9 = { 54 ab [2] 66 89 [2] 60 bc [2] 4e bc [2] 71 a0 }

  condition:
    any of them
}