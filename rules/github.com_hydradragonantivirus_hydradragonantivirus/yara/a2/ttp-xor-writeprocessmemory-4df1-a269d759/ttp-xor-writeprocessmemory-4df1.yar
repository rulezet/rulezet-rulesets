rule TTP_XOR_WriteProcessMemory_4df1 {
  strings:
    $key_4df1 = { 1a 83 [2] 28 a1 [2] 2e 94 [2] 00 94 [2] 3f 88 }

  condition:
    any of them
}