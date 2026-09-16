rule TTP_XOR_WriteProcessMemory_5dc1 {
  strings:
    $key_5dc1 = { 0a b3 [2] 38 91 [2] 3e a4 [2] 10 a4 [2] 2f b8 }

  condition:
    any of them
}