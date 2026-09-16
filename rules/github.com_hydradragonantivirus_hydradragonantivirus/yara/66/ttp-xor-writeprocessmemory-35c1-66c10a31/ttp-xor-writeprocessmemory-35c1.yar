rule TTP_XOR_WriteProcessMemory_35c1 {
  strings:
    $key_35c1 = { 62 b3 [2] 50 91 [2] 56 a4 [2] 78 a4 [2] 47 b8 }

  condition:
    any of them
}