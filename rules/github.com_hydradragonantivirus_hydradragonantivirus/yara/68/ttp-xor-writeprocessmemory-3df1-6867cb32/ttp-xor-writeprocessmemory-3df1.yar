rule TTP_XOR_WriteProcessMemory_3df1 {
  strings:
    $key_3df1 = { 6a 83 [2] 58 a1 [2] 5e 94 [2] 70 94 [2] 4f 88 }

  condition:
    any of them
}