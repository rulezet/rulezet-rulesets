rule TTP_XOR_WriteProcessMemory_cdf9 {
  strings:
    $key_cdf9 = { 9a 8b [2] a8 a9 [2] ae 9c [2] 80 9c [2] bf 80 }

  condition:
    any of them
}