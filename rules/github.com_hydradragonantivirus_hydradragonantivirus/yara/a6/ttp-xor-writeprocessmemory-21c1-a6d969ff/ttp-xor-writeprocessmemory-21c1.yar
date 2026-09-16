rule TTP_XOR_WriteProcessMemory_21c1 {
  strings:
    $key_21c1 = { 76 b3 [2] 44 91 [2] 42 a4 [2] 6c a4 [2] 53 b8 }

  condition:
    any of them
}