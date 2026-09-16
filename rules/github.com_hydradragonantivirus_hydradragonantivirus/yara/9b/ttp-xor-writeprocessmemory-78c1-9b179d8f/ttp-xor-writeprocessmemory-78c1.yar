rule TTP_XOR_WriteProcessMemory_78c1 {
  strings:
    $key_78c1 = { 2f b3 [2] 1d 91 [2] 1b a4 [2] 35 a4 [2] 0a b8 }

  condition:
    any of them
}