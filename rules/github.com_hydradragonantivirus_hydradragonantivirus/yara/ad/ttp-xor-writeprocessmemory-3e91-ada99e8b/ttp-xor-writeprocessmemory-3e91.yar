rule TTP_XOR_WriteProcessMemory_3e91 {
  strings:
    $key_3e91 = { 69 e3 [2] 5b c1 [2] 5d f4 [2] 73 f4 [2] 4c e8 }

  condition:
    any of them
}