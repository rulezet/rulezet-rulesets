rule TTP_XOR_WriteProcessMemory_0e91 {
  strings:
    $key_0e91 = { 59 e3 [2] 6b c1 [2] 6d f4 [2] 43 f4 [2] 7c e8 }

  condition:
    any of them
}