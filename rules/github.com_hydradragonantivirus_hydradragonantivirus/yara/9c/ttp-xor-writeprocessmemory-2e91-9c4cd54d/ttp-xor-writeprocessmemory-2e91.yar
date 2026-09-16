rule TTP_XOR_WriteProcessMemory_2e91 {
  strings:
    $key_2e91 = { 79 e3 [2] 4b c1 [2] 4d f4 [2] 63 f4 [2] 5c e8 }

  condition:
    any of them
}