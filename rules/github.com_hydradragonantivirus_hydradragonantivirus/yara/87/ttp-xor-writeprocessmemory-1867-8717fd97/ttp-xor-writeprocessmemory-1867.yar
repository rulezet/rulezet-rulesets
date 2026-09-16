rule TTP_XOR_WriteProcessMemory_1867 {
  strings:
    $key_1867 = { 4f 15 [2] 7d 37 [2] 7b 02 [2] 55 02 [2] 6a 1e }

  condition:
    any of them
}