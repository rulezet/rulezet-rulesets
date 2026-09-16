rule TTP_XOR_WriteProcessMemory_4855 {
  strings:
    $key_4855 = { 1f 27 [2] 2d 05 [2] 2b 30 [2] 05 30 [2] 3a 2c }

  condition:
    any of them
}