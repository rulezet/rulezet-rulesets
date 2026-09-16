rule TTP_XOR_WriteProcessMemory_1906 {
  strings:
    $key_1906 = { 4e 74 [2] 7c 56 [2] 7a 63 [2] 54 63 [2] 6b 7f }

  condition:
    any of them
}