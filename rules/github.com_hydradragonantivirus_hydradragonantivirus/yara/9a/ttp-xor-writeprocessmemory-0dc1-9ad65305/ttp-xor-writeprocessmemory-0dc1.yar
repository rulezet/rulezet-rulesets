rule TTP_XOR_WriteProcessMemory_0dc1 {
  strings:
    $key_0dc1 = { 5a b3 [2] 68 91 [2] 6e a4 [2] 40 a4 [2] 7f b8 }

  condition:
    any of them
}