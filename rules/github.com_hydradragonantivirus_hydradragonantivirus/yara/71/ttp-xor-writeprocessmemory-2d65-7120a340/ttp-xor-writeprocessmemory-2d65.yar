rule TTP_XOR_WriteProcessMemory_2d65 {
  strings:
    $key_2d65 = { 7a 17 [2] 48 35 [2] 4e 00 [2] 60 00 [2] 5f 1c }

  condition:
    any of them
}