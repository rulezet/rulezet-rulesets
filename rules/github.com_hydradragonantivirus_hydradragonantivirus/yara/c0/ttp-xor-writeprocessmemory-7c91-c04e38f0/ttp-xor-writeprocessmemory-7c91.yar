rule TTP_XOR_WriteProcessMemory_7c91 {
  strings:
    $key_7c91 = { 2b e3 [2] 19 c1 [2] 1f f4 [2] 31 f4 [2] 0e e8 }

  condition:
    any of them
}