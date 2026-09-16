rule TTP_XOR_WriteProcessMemory_6d91 {
  strings:
    $key_6d91 = { 3a e3 [2] 08 c1 [2] 0e f4 [2] 20 f4 [2] 1f e8 }

  condition:
    any of them
}