rule TTP_XOR_WriteProcessMemory_cdf7 {
  strings:
    $key_cdf7 = { 9a 85 [2] a8 a7 [2] ae 92 [2] 80 92 [2] bf 8e }

  condition:
    any of them
}