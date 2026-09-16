rule TTP_XOR_WriteProcessMemory_31c1 {
  strings:
    $key_31c1 = { 66 b3 [2] 54 91 [2] 52 a4 [2] 7c a4 [2] 43 b8 }

  condition:
    any of them
}