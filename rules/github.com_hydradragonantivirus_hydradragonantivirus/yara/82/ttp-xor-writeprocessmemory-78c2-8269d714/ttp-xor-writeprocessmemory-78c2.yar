rule TTP_XOR_WriteProcessMemory_78c2 {
  strings:
    $key_78c2 = { 2f b0 [2] 1d 92 [2] 1b a7 [2] 35 a7 [2] 0a bb }

  condition:
    any of them
}