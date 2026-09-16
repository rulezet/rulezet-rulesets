rule TTP_XOR_WriteProcessMemory_1251 {
  strings:
    $key_1251 = { 45 23 [2] 77 01 [2] 71 34 [2] 5f 34 [2] 60 28 }

  condition:
    any of them
}