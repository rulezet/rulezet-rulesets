rule TTP_XOR_WriteProcessMemory_1806 {
  strings:
    $key_1806 = { 4f 74 [2] 7d 56 [2] 7b 63 [2] 55 63 [2] 6a 7f }

  condition:
    any of them
}