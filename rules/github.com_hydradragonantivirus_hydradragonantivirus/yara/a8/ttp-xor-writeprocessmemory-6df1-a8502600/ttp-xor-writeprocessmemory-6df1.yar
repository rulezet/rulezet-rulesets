rule TTP_XOR_WriteProcessMemory_6df1 {
  strings:
    $key_6df1 = { 3a 83 [2] 08 a1 [2] 0e 94 [2] 20 94 [2] 1f 88 }

  condition:
    any of them
}