rule TTP_XOR_WriteProcessMemory_7e91 {
  strings:
    $key_7e91 = { 29 e3 [2] 1b c1 [2] 1d f4 [2] 33 f4 [2] 0c e8 }

  condition:
    any of them
}