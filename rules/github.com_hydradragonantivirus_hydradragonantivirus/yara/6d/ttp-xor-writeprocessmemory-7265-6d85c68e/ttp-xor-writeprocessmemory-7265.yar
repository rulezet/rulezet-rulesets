rule TTP_XOR_WriteProcessMemory_7265 {
  strings:
    $key_7265 = { 25 17 [2] 17 35 [2] 11 00 [2] 3f 00 [2] 00 1c }

  condition:
    any of them
}