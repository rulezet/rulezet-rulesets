rule TTP_XOR_WriteProcessMemory_0cc2 {
  strings:
    $key_0cc2 = { 5b b0 [2] 69 92 [2] 6f a7 [2] 41 a7 [2] 7e bb }

  condition:
    any of them
}