rule TTP_XOR_WriteProcessMemory_18c1 {
  strings:
    $key_18c1 = { 4f b3 [2] 7d 91 [2] 7b a4 [2] 55 a4 [2] 6a b8 }

  condition:
    any of them
}