rule TTP_XOR_WriteProcessMemory_5d65 {
  strings:
    $key_5d65 = { 0a 17 [2] 38 35 [2] 3e 00 [2] 10 00 [2] 2f 1c }

  condition:
    any of them
}