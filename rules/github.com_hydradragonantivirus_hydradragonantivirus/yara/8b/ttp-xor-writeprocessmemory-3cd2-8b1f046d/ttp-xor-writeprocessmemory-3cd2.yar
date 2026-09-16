rule TTP_XOR_WriteProcessMemory_3cd2 {
  strings:
    $key_3cd2 = { 6b a0 [2] 59 82 [2] 5f b7 [2] 71 b7 [2] 4e ab }

  condition:
    any of them
}