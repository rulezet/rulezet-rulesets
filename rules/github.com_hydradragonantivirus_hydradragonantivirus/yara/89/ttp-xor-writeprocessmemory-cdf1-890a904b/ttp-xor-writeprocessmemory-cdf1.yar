rule TTP_XOR_WriteProcessMemory_cdf1 {
  strings:
    $key_cdf1 = { 9a 83 [2] a8 a1 [2] ae 94 [2] 80 94 [2] bf 88 }

  condition:
    any of them
}