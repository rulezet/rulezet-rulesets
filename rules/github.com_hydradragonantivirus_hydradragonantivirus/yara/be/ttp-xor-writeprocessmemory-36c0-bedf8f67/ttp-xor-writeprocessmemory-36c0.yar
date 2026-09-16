rule TTP_XOR_WriteProcessMemory_36c0 {
  strings:
    $key_36c0 = { 61 b2 [2] 53 90 [2] 55 a5 [2] 7b a5 [2] 44 b9 }

  condition:
    any of them
}