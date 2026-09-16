rule TTP_XOR_WriteProcessMemory_2cc2 {
  strings:
    $key_2cc2 = { 7b b0 [2] 49 92 [2] 4f a7 [2] 61 a7 [2] 5e bb }

  condition:
    any of them
}