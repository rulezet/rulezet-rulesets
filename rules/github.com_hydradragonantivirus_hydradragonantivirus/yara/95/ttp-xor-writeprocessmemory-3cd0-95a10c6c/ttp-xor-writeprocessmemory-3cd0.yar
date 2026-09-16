rule TTP_XOR_WriteProcessMemory_3cd0 {
  strings:
    $key_3cd0 = { 6b a2 [2] 59 80 [2] 5f b5 [2] 71 b5 [2] 4e a9 }

  condition:
    any of them
}