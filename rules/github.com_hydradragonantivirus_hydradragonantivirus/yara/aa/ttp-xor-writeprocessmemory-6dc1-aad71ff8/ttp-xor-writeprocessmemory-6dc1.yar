rule TTP_XOR_WriteProcessMemory_6dc1 {
  strings:
    $key_6dc1 = { 3a b3 [2] 08 91 [2] 0e a4 [2] 20 a4 [2] 1f b8 }

  condition:
    any of them
}