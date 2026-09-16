rule TTP_XOR_WriteProcessMemory_48c2 {
  strings:
    $key_48c2 = { 1f b0 [2] 2d 92 [2] 2b a7 [2] 05 a7 [2] 3a bb }

  condition:
    any of them
}