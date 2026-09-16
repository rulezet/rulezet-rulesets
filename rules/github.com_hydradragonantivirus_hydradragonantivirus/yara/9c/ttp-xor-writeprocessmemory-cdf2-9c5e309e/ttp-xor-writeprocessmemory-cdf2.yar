rule TTP_XOR_WriteProcessMemory_cdf2 {
  strings:
    $key_cdf2 = { 9a 80 [2] a8 a2 [2] ae 97 [2] 80 97 [2] bf 8b }

  condition:
    any of them
}