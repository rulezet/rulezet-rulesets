rule TTP_XOR_WriteProcessMemory_26c1 {
  strings:
    $key_26c1 = { 71 b3 [2] 43 91 [2] 45 a4 [2] 6b a4 [2] 54 b8 }

  condition:
    any of them
}