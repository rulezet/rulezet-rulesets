rule TTP_XOR_WriteProcessMemory_66c1 {
  strings:
    $key_66c1 = { 31 b3 [2] 03 91 [2] 05 a4 [2] 2b a4 [2] 14 b8 }

  condition:
    any of them
}