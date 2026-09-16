rule TTP_XOR_WriteProcessMemory_5c91 {
  strings:
    $key_5c91 = { 0b e3 [2] 39 c1 [2] 3f f4 [2] 11 f4 [2] 2e e8 }

  condition:
    any of them
}