rule TTP_XOR_WriteProcessMemory_6e91 {
  strings:
    $key_6e91 = { 39 e3 [2] 0b c1 [2] 0d f4 [2] 23 f4 [2] 1c e8 }

  condition:
    any of them
}