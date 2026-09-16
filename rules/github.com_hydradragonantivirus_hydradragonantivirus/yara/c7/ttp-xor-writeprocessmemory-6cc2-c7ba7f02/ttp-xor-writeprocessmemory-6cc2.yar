rule TTP_XOR_WriteProcessMemory_6cc2 {
  strings:
    $key_6cc2 = { 3b b0 [2] 09 92 [2] 0f a7 [2] 21 a7 [2] 1e bb }

  condition:
    any of them
}