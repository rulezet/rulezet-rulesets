rule TTP_XOR_WriteProcessMemory_1851 {
  strings:
    $key_1851 = { 4f 23 [2] 7d 01 [2] 7b 34 [2] 55 34 [2] 6a 28 }

  condition:
    any of them
}