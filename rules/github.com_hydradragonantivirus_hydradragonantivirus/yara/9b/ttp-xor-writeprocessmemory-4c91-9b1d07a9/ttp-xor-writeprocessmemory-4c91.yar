rule TTP_XOR_WriteProcessMemory_4c91 {
  strings:
    $key_4c91 = { 1b e3 [2] 29 c1 [2] 2f f4 [2] 01 f4 [2] 3e e8 }

  condition:
    any of them
}