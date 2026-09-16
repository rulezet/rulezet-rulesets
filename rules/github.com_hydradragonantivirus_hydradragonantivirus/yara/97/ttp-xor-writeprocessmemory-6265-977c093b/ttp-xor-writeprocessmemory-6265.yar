rule TTP_XOR_WriteProcessMemory_6265 {
  strings:
    $key_6265 = { 35 17 [2] 07 35 [2] 01 00 [2] 2f 00 [2] 10 1c }

  condition:
    any of them
}