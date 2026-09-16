rule TTP_XOR_WriteProcessMemory_cdf3 {
  strings:
    $key_cdf3 = { 9a 81 [2] a8 a3 [2] ae 96 [2] 80 96 [2] bf 8a }

  condition:
    any of them
}