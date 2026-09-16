rule TTP_XOR_WriteProcessMemory_0d91 {
  strings:
    $key_0d91 = { 5a e3 [2] 68 c1 [2] 6e f4 [2] 40 f4 [2] 7f e8 }

  condition:
    any of them
}