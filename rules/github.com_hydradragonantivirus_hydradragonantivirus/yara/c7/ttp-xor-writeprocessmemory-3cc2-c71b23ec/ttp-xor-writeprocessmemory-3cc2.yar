rule TTP_XOR_WriteProcessMemory_3cc2 {
  strings:
    $key_3cc2 = { 6b b0 [2] 59 92 [2] 5f a7 [2] 71 a7 [2] 4e bb }

  condition:
    any of them
}