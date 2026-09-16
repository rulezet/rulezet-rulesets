rule TTP_XOR_WriteProcessMemory_11c1 {
  strings:
    $key_11c1 = { 46 b3 [2] 74 91 [2] 72 a4 [2] 5c a4 [2] 63 b8 }

  condition:
    any of them
}