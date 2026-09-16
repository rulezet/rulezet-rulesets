rule TTP_XOR_WriteProcessMemory_5df1 {
  strings:
    $key_5df1 = { 0a 83 [2] 38 a1 [2] 3e 94 [2] 10 94 [2] 2f 88 }

  condition:
    any of them
}