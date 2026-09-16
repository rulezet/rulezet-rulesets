rule TTP_XOR_WriteProcessMemory_66c0 {
  strings:
    $key_66c0 = { 31 b2 [2] 03 90 [2] 05 a5 [2] 2b a5 [2] 14 b9 }

  condition:
    any of them
}