rule TTP_XOR_WriteProcessMemory_1df1 {
  strings:
    $key_1df1 = { 4a 83 [2] 78 a1 [2] 7e 94 [2] 50 94 [2] 6f 88 }

  condition:
    any of them
}