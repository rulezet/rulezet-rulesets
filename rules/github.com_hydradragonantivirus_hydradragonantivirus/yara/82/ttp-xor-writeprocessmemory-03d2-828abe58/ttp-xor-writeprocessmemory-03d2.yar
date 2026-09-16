rule TTP_XOR_WriteProcessMemory_03d2 {
  strings:
    $key_03d2 = { 54 a0 [2] 66 82 [2] 60 b7 [2] 4e b7 [2] 71 ab }

  condition:
    any of them
}