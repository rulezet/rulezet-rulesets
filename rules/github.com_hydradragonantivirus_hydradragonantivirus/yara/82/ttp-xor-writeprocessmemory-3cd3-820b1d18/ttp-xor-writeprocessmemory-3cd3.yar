rule TTP_XOR_WriteProcessMemory_3cd3 {
  strings:
    $key_3cd3 = { 6b a1 [2] 59 83 [2] 5f b6 [2] 71 b6 [2] 4e aa }

  condition:
    any of them
}