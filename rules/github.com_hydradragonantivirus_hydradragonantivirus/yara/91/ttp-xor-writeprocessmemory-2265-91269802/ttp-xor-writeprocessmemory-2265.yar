rule TTP_XOR_WriteProcessMemory_2265 {
  strings:
    $key_2265 = { 75 17 [2] 47 35 [2] 41 00 [2] 6f 00 [2] 50 1c }

  condition:
    any of them
}