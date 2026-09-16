rule TTP_XOR_WriteProcessMemory_4361 {
  strings:
    $key_4361 = { 14 13 [2] 26 31 [2] 20 04 [2] 0e 04 [2] 31 18 }

  condition:
    any of them
}