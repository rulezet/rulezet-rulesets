rule TTP_XOR_WriteProcessMemory_4e91 {
  strings:
    $key_4e91 = { 19 e3 [2] 2b c1 [2] 2d f4 [2] 03 f4 [2] 3c e8 }

  condition:
    any of them
}